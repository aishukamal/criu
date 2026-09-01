Checkpoint and Restore for TPU applications with CRIU
======================================================

# Requirements
The workload's TPU runtime must support the tpu_control checkpoint/restore
protocol. The plugin detects support by the presence of the libtpu control
thread in the workload process.

# Control Protocol
libtpu advertises its control channel by naming a thread
"libtpu{XXXXYYYY}" in the workload process, where the 8-character hex
suffix encodes the request-write and response-read pipe FD numbers. The
plugin discovers this thread by scanning /proc/<pid>/task/*/comm and
exchanges length-delimited protobuf control messages over the pipes,
accessed via /proc/<pid>/fd/.

The canonical schema for the control messages is
pkg/sentry/control/tpu_control.proto in the gVisor tree:
https://github.com/google/gvisor

# Checkpointing Procedure
The plugin issues 2 actions in the checkpointing process: checkpoint,
restore.

* checkpoint - Used with the CHECKPOINT_DEVICES hook once a process has been
  seized/frozen to perform the actual checkpointing operation. libtpu moves
  the HBM contents of all attached TPU chips into buffers in the process's
  host memory and closes its TPU device file descriptors, so CRIU's normal
  memory dump captures the device state and no TPU device files remain open
  at dump time.
* restore - Used with the RESUME_DEVICES_LATE hook to reattach the TPU
  devices and copy the HBM contents back.

These actions are serviced by the libtpu control thread inside the target
process, which the TPU plugin resumes when needed while the rest of the
process stays frozen.

# Known Limitations
* The PAUSE_DEVICES hook does not quiesce the device: it does not gate new
  TPU work or drain in-flight programs the way the CUDA plugin's lock
  action does. The caller must guarantee the workload is TPU-idle before
  dumping. The tpu_control protocol defines a lock action, and this hook is
  the natural place to invoke it, mirroring the CUDA plugin.
* TPU memory contents are brought into main system memory and CRIU then
  checkpoints that as part of the normal procedure. HBM capacity can be
  large (tens to hundreds of GiB per host), so ensure the host has enough
  free memory headroom for the dump.
* Restore requires a system with identical TPU topology (chip architecture,
  chip count, and interconnect mesh shape).
