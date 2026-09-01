#include "criu-log.h"
#include "plugin.h"
#include "util.h"
#include "cr_options.h"
#include "pid.h"
#include "proc_parse.h"
#include "seize.h"

#include <common/list.h>
#include <compel/infect.h>

#include <ctype.h>
#include <dirent.h>
#include <fcntl.h>
#include <limits.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/stat.h>

/* libtpu advertises its control channel with a thread named
 * "libtpu{XXXXYYYY}" where the 8-character hex suffix encodes the
 * request-write and response-read pipe FDs. comm names are at most 15
 * characters, and "libtpu" + 8 hex characters is exactly 14.
 *
 * Control messages are length-delimited protobufs (4-byte big-endian size
 * prefix). The canonical schema is pkg/sentry/control/tpu_control.proto in
 * the gVisor tree; the field numbers and enum values used below mirror it.
 * Unknown response fields are skipped, so schema additions are compatible.
 */
#define TPU_THREAD_PREFIX     "libtpu"
#define TPU_THREAD_PREFIX_LEN 6
#define TPU_THREAD_HEX_LEN    8
#define TPU_THREAD_NAME_LEN   (TPU_THREAD_PREFIX_LEN + TPU_THREAD_HEX_LEN)

/* One control thread per libtpu client is expected today; leave headroom. */
#define TPU_MAX_CONTROL_THREADS 16

/* ControlAction values (tpu_control.proto). */
#define TPU_ACTION_CHECKPOINT 2
#define TPU_ACTION_RESTORE    3

/* ControlRequest field tags: field 1 (action) and field 2 (timeout_secs),
 * both varint (wire type 0).
 */
#define TPU_REQ_TAG_ACTION  0x08
#define TPU_REQ_TAG_TIMEOUT 0x10

/* ControlResponse field numbers. */
#define TPU_RSP_FIELD_SUCCESS 1
#define TPU_RSP_FIELD_STATE   2
#define TPU_RSP_FIELD_ERROR   3

#define TPU_DEFAULT_TIMEOUT_SECS 180

/* Bounds a response message, as a defense against a corrupted size prefix. */
#define TPU_MAX_RSP_BYTES (1 << 20)

#ifdef LOG_PREFIX
#undef LOG_PREFIX
#endif
#define LOG_PREFIX "tpu_plugin: "

/* Disable plugin functionality if no TPU device is present. */
static bool plugin_disabled = false;

static bool plugin_added_to_inventory = false;

struct pid_info {
	int pid;
	char checkpointed;
	struct list_head list;
};

/* Tracks the PIDs with libtpu control threads seen during DUMP so their
 * device state can be restored if the user requested the leave-running
 * option or an error occurred.
 */
static LIST_HEAD(tpu_pids);

struct tpu_ctl_thread {
	int tid;
	int req_write_fd;
	int rsp_read_fd;
};

struct tpu_ctl_response {
	bool success;
	uint64_t state;
	char error[256];
};

static void dealloc_pid_buffer(struct list_head *pid_buf)
{
	struct pid_info *info;
	struct pid_info *n;

	list_for_each_entry_safe(info, n, pid_buf, list) {
		list_del(&info->list);
		xfree(info);
	}
}

static int add_pid_to_buf(struct list_head *pid_buf, int pid)
{
	struct pid_info *new = xmalloc(sizeof(*new));

	if (new == NULL) {
		return -1;
	}

	new->pid = pid;
	new->checkpointed = 0;
	list_add_tail(&new->list, pid_buf);

	return 0;
}

static struct pid_info *find_pid_in_buf(struct list_head *pid_buf, int pid)
{
	struct pid_info *info;

	list_for_each_entry(info, pid_buf, list) {
		if (info->pid == pid)
			return info;
	}

	return NULL;
}

static const char *tpu_action_name(int action)
{
	switch (action) {
	case TPU_ACTION_CHECKPOINT:
		return "checkpoint";
	case TPU_ACTION_RESTORE:
		return "restore";
	default:
		return "action";
	}
}

/* Find the libtpu control threads of a process by scanning
 * /proc/<pid>/task/<tid>/comm for the "libtpu{XXXXYYYY}" naming pattern
 * and decode the pipe FD numbers from the hex suffix.
 *
 * Returns the number of control threads found (0 if the process is not a
 * TPU workload), or -1 on error.
 */
static int find_libtpu_threads(int pid, struct tpu_ctl_thread *threads, int max_threads)
{
	char path[64];
	DIR *dir;
	struct dirent *ent;
	int n = 0;

	snprintf(path, sizeof(path), "/proc/%d/task", pid);
	dir = opendir(path);
	if (dir == NULL) {
		pr_perror("Failed to open %s", path);
		return -1;
	}

	while (n < max_threads && (ent = readdir(dir)) != NULL) {
		char comm_path[sizeof("/proc/2147483647/task//comm") + NAME_MAX];
		char comm[32];
		char hex[5];
		FILE *f;
		int i, len;
		long req_fd, rsp_fd;

		if (!isdigit(ent->d_name[0]))
			continue;

		snprintf(comm_path, sizeof(comm_path), "/proc/%d/task/%s/comm", pid, ent->d_name);
		f = fopen(comm_path, "r");
		if (f == NULL)
			continue;
		if (fgets(comm, sizeof(comm), f) == NULL) {
			fclose(f);
			continue;
		}
		fclose(f);

		len = strlen(comm);
		if (len > 0 && comm[len - 1] == '\n')
			comm[--len] = '\0';

		if (len != TPU_THREAD_NAME_LEN)
			continue;
		if (strncmp(comm, TPU_THREAD_PREFIX, TPU_THREAD_PREFIX_LEN) != 0)
			continue;
		for (i = TPU_THREAD_PREFIX_LEN; i < TPU_THREAD_NAME_LEN; i++) {
			if (!isxdigit(comm[i]))
				break;
		}
		if (i != TPU_THREAD_NAME_LEN)
			continue;

		memcpy(hex, comm + TPU_THREAD_PREFIX_LEN, 4);
		hex[4] = '\0';
		req_fd = strtol(hex, NULL, 16);
		memcpy(hex, comm + TPU_THREAD_PREFIX_LEN + 4, 4);
		hex[4] = '\0';
		rsp_fd = strtol(hex, NULL, 16);

		threads[n].tid = atoi(ent->d_name);
		threads[n].req_write_fd = (int)req_fd;
		threads[n].rsp_read_fd = (int)rsp_fd;
		n++;
	}

	closedir(dir);
	return n;
}

static int encode_varint(uint8_t *buf, uint64_t v)
{
	int n = 0;

	while (v >= 0x80) {
		buf[n++] = (uint8_t)v | 0x80;
		v >>= 7;
	}
	buf[n++] = (uint8_t)v;
	return n;
}

static int decode_varint(const uint8_t *p, size_t n, uint64_t *out)
{
	uint64_t v = 0;
	size_t i;

	for (i = 0; i < n && i < 10; i++) {
		v |= (uint64_t)(p[i] & 0x7f) << (7 * i);
		if (!(p[i] & 0x80)) {
			*out = v;
			return (int)i + 1;
		}
	}
	return -1;
}

/* Encode a ControlRequest{action, timeout_secs} into buf (which must have
 * room for two tagged varints; 24 bytes is plenty). Returns the length.
 */
static int tpu_encode_request(uint8_t *buf, int action, int timeout_secs)
{
	int n = 0;

	buf[n++] = TPU_REQ_TAG_ACTION;
	n += encode_varint(buf + n, (uint64_t)action);
	if (timeout_secs > 0) {
		buf[n++] = TPU_REQ_TAG_TIMEOUT;
		n += encode_varint(buf + n, (uint64_t)timeout_secs);
	}
	return n;
}

/* Decode a ControlResponse, extracting success, current_state and
 * error_message. Unknown fields are skipped by wire type.
 */
static int tpu_decode_response(const uint8_t *p, size_t n, struct tpu_ctl_response *rsp)
{
	memset(rsp, 0, sizeof(*rsp));

	while (n > 0) {
		uint64_t tag, val, len;
		int k;

		k = decode_varint(p, n, &tag);
		if (k < 0)
			return -1;
		p += k;
		n -= k;

		switch (tag & 7) {
		case 0: /* varint */
			k = decode_varint(p, n, &val);
			if (k < 0)
				return -1;
			p += k;
			n -= k;
			if ((tag >> 3) == TPU_RSP_FIELD_SUCCESS)
				rsp->success = val != 0;
			else if ((tag >> 3) == TPU_RSP_FIELD_STATE)
				rsp->state = val;
			break;
		case 2: /* length-delimited */
			k = decode_varint(p, n, &len);
			if (k < 0)
				return -1;
			p += k;
			n -= k;
			if (len > n)
				return -1;
			if ((tag >> 3) == TPU_RSP_FIELD_ERROR) {
				size_t c = len < sizeof(rsp->error) - 1 ? len : sizeof(rsp->error) - 1;

				memcpy(rsp->error, p, c);
				rsp->error[c] = '\0';
			}
			p += len;
			n -= len;
			break;
		case 1: /* fixed64 */
			if (n < 8)
				return -1;
			p += 8;
			n -= 8;
			break;
		case 5: /* fixed32 */
			if (n < 4)
				return -1;
			p += 4;
			n -= 4;
			break;
		default:
			return -1;
		}
	}
	return 0;
}

static int write_full(int fd, const uint8_t *buf, size_t n)
{
	size_t off = 0;

	while (off < n) {
		ssize_t w = write(fd, buf + off, n - off);

		if (w < 0) {
			pr_perror("Failed to write control request");
			return -1;
		}
		off += w;
	}
	return 0;
}

static int read_full_timeout(int fd, uint8_t *buf, size_t want, int timeout_ms)
{
	size_t off = 0;

	while (off < want) {
		struct pollfd pfd = {
			.fd = fd,
			.events = POLLIN,
		};
		ssize_t r;
		int pr;

		pr = poll(&pfd, 1, timeout_ms);
		if (pr < 0) {
			pr_perror("Failed to poll control response pipe");
			return -1;
		}
		if (pr == 0) {
			pr_err("Timed out waiting for control response\n");
			return -1;
		}
		r = read(fd, buf + off, want - off);
		if (r < 0) {
			pr_perror("Failed to read control response");
			return -1;
		}
		if (r == 0) {
			pr_err("Control response pipe closed unexpectedly\n");
			return -1;
		}
		off += r;
	}
	return 0;
}

/* Exchange one ControlRequest/ControlResponse with a libtpu control thread
 * over its pipes, accessed via /proc/<pid>/fd/.
 */
static int tpu_ctl_exchange(int pid, struct tpu_ctl_thread *t, int action, int timeout_secs)
{
	char path[64];
	uint8_t req[4 + 24];
	uint8_t hdr[4];
	uint8_t *rsp_buf = NULL;
	struct tpu_ctl_response rsp;
	uint32_t rsp_len;
	int req_fd = -1, rsp_fd = -1;
	int timeout_ms = (timeout_secs > 0 ? timeout_secs : TPU_DEFAULT_TIMEOUT_SECS) * 1000;
	int n, ret = -1;

	snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, t->req_write_fd);
	req_fd = open(path, O_WRONLY);
	if (req_fd < 0) {
		pr_perror("Failed to open request pipe %s", path);
		goto out;
	}

	snprintf(path, sizeof(path), "/proc/%d/fd/%d", pid, t->rsp_read_fd);
	rsp_fd = open(path, O_RDONLY);
	if (rsp_fd < 0) {
		pr_perror("Failed to open response pipe %s", path);
		goto out;
	}

	n = tpu_encode_request(req + 4, action, timeout_secs);
	req[0] = (uint8_t)(n >> 24);
	req[1] = (uint8_t)(n >> 16);
	req[2] = (uint8_t)(n >> 8);
	req[3] = (uint8_t)n;

	if (write_full(req_fd, req, 4 + n))
		goto out;

	if (read_full_timeout(rsp_fd, hdr, sizeof(hdr), timeout_ms))
		goto out;
	rsp_len = ((uint32_t)hdr[0] << 24) | ((uint32_t)hdr[1] << 16) | ((uint32_t)hdr[2] << 8) | hdr[3];
	if (rsp_len > TPU_MAX_RSP_BYTES) {
		pr_err("Control response too large: %u bytes\n", rsp_len);
		goto out;
	}

	rsp_buf = xmalloc(rsp_len);
	if (rsp_buf == NULL)
		goto out;
	if (read_full_timeout(rsp_fd, rsp_buf, rsp_len, timeout_ms))
		goto out;

	if (tpu_decode_response(rsp_buf, rsp_len, &rsp)) {
		pr_err("Failed to decode control response from tid %d\n", t->tid);
		goto out;
	}

	if (!rsp.success) {
		pr_err("TPU %s failed on tid %d: %s\n", tpu_action_name(action), t->tid,
		       rsp.error[0] ? rsp.error : "unknown error");
		goto out;
	}

	ret = 0;
out:
	if (req_fd >= 0)
		close(req_fd);
	if (rsp_fd >= 0)
		close(rsp_fd);
	xfree(rsp_buf);
	return ret;
}

static int interrupt_control_thread(int tid, k_rtsigset_t *sigset)
{
	/* Since we resumed a thread that CRIU previously already froze we need to
	 * INTERRUPT it once again, task was already SEIZE'd so we don't need to do
	 * a compel_interrupt_task()
	 */
	if (ptrace(PTRACE_INTERRUPT, tid, NULL, 0)) {
		pr_perror("Could not interrupt libtpu control tid %d, process may be in strange state", tid);
		return -1;
	}

	struct proc_status_creds creds;
	if (compel_wait_task(tid, -1, parse_pid_status, NULL, &creds.s, NULL) != COMPEL_TASK_ALIVE) {
		pr_err("compel_wait_task failed after interrupt\n");
		return -1;
	}

	if (ptrace(PTRACE_SETOPTIONS, tid, NULL, PTRACE_O_SUSPEND_SECCOMP | PTRACE_O_TRACESYSGOOD)) {
		pr_perror("Failed to set ptrace options on interrupt for libtpu control tid %d", tid);
		return -1;
	}

	if (ptrace(PTRACE_SETSIGMASK, tid, sizeof(*sigset), sigset)) {
		pr_perror("Unable to restore original sigmask to libtpu control tid %d", tid);
		return -1;
	}

	return 0;
}

static int resume_control_thread(int tid, k_rtsigset_t *save_sigset)
{
	k_rtsigset_t block;

	if (ptrace(PTRACE_GETSIGMASK, tid, sizeof(*save_sigset), save_sigset)) {
		pr_perror("Failed to get current sigmask for libtpu control tid %d", tid);
		return -1;
	}

	ksigfillset(&block);
	ksigdelset(&block, SIGTRAP);

	if (ptrace(PTRACE_SETSIGMASK, tid, sizeof(block), &block)) {
		pr_perror("Failed to block signals on libtpu control tid %d", tid);
		return -1;
	}

	// Clear out PTRACE_O_SUSPEND_SECCOMP when we resume the control thread
	if (ptrace(PTRACE_SETOPTIONS, tid, NULL, 0)) {
		pr_perror("Could not clear ptrace options on libtpu control tid %d", tid);
		return -1;
	}

	if (ptrace(PTRACE_CONT, tid, NULL, 0)) {
		pr_perror("Could not resume libtpu control tid %d", tid);
		return -1;
	}

	return 0;
}

/* Run a control action against a frozen process. The libtpu control
 * threads must be running to service the request, so resume them for the
 * duration of the action and interrupt them again afterwards.
 */
static int tpu_run_action_frozen(int pid, int action, unsigned int timeout)
{
	struct tpu_ctl_thread threads[TPU_MAX_CONTROL_THREADS];
	k_rtsigset_t sigsets[TPU_MAX_CONTROL_THREADS];
	int n_threads, i, resumed;
	int status = 0;
	int int_ret = 0;

	n_threads = find_libtpu_threads(pid, threads, TPU_MAX_CONTROL_THREADS);
	if (n_threads < 0)
		return -1;
	if (n_threads == 0) {
		pr_debug("No libtpu control threads on pid %d\n", pid);
		return 0;
	}

	for (resumed = 0; resumed < n_threads; resumed++) {
		if (resume_control_thread(threads[resumed].tid, &sigsets[resumed])) {
			status = -1;
			goto interrupt;
		}
	}

	for (i = 0; i < n_threads; i++) {
		if (tpu_ctl_exchange(pid, &threads[i], action, timeout))
			status = -1;
	}

interrupt:
	for (i = 0; i < resumed; i++) {
		if (interrupt_control_thread(threads[i].tid, &sigsets[i]))
			int_ret = -1;
	}

	return status != 0 ? status : int_ret;
}

int tpu_plugin_pause_devices(int pid)
{
	struct tpu_ctl_thread threads[TPU_MAX_CONTROL_THREADS];
	int n_threads;

	if (plugin_disabled) {
		return -ENOTSUP;
	}

	n_threads = find_libtpu_threads(pid, threads, TPU_MAX_CONTROL_THREADS);
	if (n_threads < 0)
		return -1;
	if (n_threads == 0) {
		pr_info("no need to pause devices on pid %d\n", pid);
		return 0;
	}

	/* This hook does not quiesce the device: it does not gate new TPU
	 * work or drain in-flight programs. The caller must guarantee the
	 * workload is TPU-idle before dumping. The tpu_control protocol
	 * defines a lock action, and this hook is the natural place to
	 * invoke it, mirroring the CUDA plugin.
	 */
	pr_warn("TPU quiesce is not performed; pid %d must be TPU-idle before dump\n", pid);

	if (!plugin_added_to_inventory) {
		if (add_inventory_plugin(CR_PLUGIN_DESC.name)) {
			pr_err("Failed to add TPU plugin to inventory image\n");
			return -1;
		}
		plugin_added_to_inventory = true;
	}

	if (add_pid_to_buf(&tpu_pids, pid)) {
		pr_err("unable to track pid %d\n", pid);
		return -1;
	}

	return 0;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__PAUSE_DEVICES, tpu_plugin_pause_devices)

int tpu_plugin_checkpoint_devices(int pid)
{
	struct pid_info *task_info;
	int ret;

	if (plugin_disabled) {
		return -ENOTSUP;
	}

	task_info = find_pid_in_buf(&tpu_pids, pid);
	if (task_info == NULL) {
		/* The process had no libtpu control threads at PAUSE_DEVICES
		 * time (or gained them since; libtpu initialization after the
		 * pause is not checkpointable in this pass).
		 */
		pr_info("No need to checkpoint devices on pid %d\n", pid);
		return 0;
	}

	pr_info("Checkpointing TPU state on pid %d\n", pid);

	ret = tpu_run_action_frozen(pid, TPU_ACTION_CHECKPOINT, opts.timeout);
	if (ret == 0)
		task_info->checkpointed = 1;

	return ret;
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__CHECKPOINT_DEVICES, tpu_plugin_checkpoint_devices);

static int resume_device(int pid, int checkpointed)
{
	if (!checkpointed)
		return 0;

	pr_info("resuming devices on pid %d\n", pid);

	/* The resuming process has to stay frozen during this time otherwise
	 * accessing TPU state before the HBM contents are restored will fault.
	 */
	return tpu_run_action_frozen(pid, TPU_ACTION_RESTORE, opts.timeout);
}

int tpu_plugin_resume_devices_late(int pid)
{
	if (plugin_disabled) {
		return -ENOTSUP;
	}

	return resume_device(pid, 1);
}
CR_PLUGIN_REGISTER_HOOK(CR_PLUGIN_HOOK__RESUME_DEVICES_LATE, tpu_plugin_resume_devices_late)

/**
 * Check if a TPU device is available on the system.
 *
 * TPUs are PCI devices with the Google vendor ID (0x1ae0).
 */
static bool is_tpu_device_available(void)
{
	const char *pci_path = "/sys/bus/pci/devices";
	DIR *dir;
	struct dirent *ent;
	bool found = false;

	dir = opendir(pci_path);
	if (dir == NULL)
		return false;

	while (!found && (ent = readdir(dir)) != NULL) {
		char vendor_path[512];
		char vendor[16];
		FILE *f;

		if (ent->d_name[0] == '.')
			continue;

		snprintf(vendor_path, sizeof(vendor_path), "%s/%s/vendor", pci_path, ent->d_name);
		f = fopen(vendor_path, "r");
		if (f == NULL)
			continue;
		if (fgets(vendor, sizeof(vendor), f) != NULL && strncmp(vendor, "0x1ae0", 6) == 0)
			found = true;
		fclose(f);
	}

	closedir(dir);
	return found;
}

int tpu_plugin_init(int stage)
{
	/* Disable TPU checkpointing with pre-dump */
	if (stage == CR_PLUGIN_STAGE__PRE_DUMP) {
		plugin_disabled = true;
		return 0;
	}

	if (stage == CR_PLUGIN_STAGE__RESTORE) {
		if (!check_and_remove_inventory_plugin(CR_PLUGIN_DESC.name, strlen(CR_PLUGIN_DESC.name))) {
			plugin_disabled = true;
			return 0;
		}
	}

	if (!is_tpu_device_available()) {
		pr_info("No TPU device found; TPU plugin is disabled\n");
		plugin_disabled = true;
		return 0;
	}

	pr_info("initialized: %s stage %d\n", CR_PLUGIN_DESC.name, stage);

	/* In the DUMP stage track all the PIDs with libtpu control threads to
	 * restore their device state when we're done if the user requested the
	 * leave-running option
	 */
	if (stage == CR_PLUGIN_STAGE__DUMP) {
		INIT_LIST_HEAD(&tpu_pids);
	}

	set_compel_interrupt_only_mode();

	return 0;
}

void tpu_plugin_fini(int stage, int ret)
{
	if (plugin_disabled) {
		return;
	}

	pr_info("finished %s stage %d err %d\n", CR_PLUGIN_DESC.name, stage, ret);

	/* Restore the device state of all checkpointed PIDs at the end of the
	 * DUMP stage in case the user provides the -R (leave-running) flag or
	 * an error occurred
	 */
	if (stage == CR_PLUGIN_STAGE__DUMP && (opts.final_state == TASK_ALIVE || ret != 0)) {
		struct pid_info *info;
		list_for_each_entry(info, &tpu_pids, list) {
			resume_device(info->pid, info->checkpointed);
		}
	}
	if (stage == CR_PLUGIN_STAGE__DUMP) {
		dealloc_pid_buffer(&tpu_pids);
	}
}
CR_PLUGIN_REGISTER("tpu_plugin", tpu_plugin_init, tpu_plugin_fini)
