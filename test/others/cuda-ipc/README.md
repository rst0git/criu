# CUDA IPC checkpoint workload

Two processes on one GPU keep a real `cuIpcGetMemHandle` / `cuIpcOpenMemHandle`
mapping open across checkpoint/restore. The owner exports a 16 KiB allocation.
The importer reads it and writes back through the imported mapping. After
restore, the owner checks the saved contents before either peer overwrites them;
both peers then repeat the exchange with a different pattern.

## Run

Requires Linux, a C compiler, CUDA headers and libcuda, Python 3, and
`cuda-checkpoint` on PATH. The supported IPC checkpoint path requires NVIDIA
r610 or newer. No full CRIU build or root access is needed for these same-user
CUDA-only tests.

From the CRIU repository:

```bash
make -C test/others/cuda-ipc test
```

Or, from this directory (also works when these files are copied elsewhere):

```bash
make test
```

Set `CUDA_HOME=/path/to/cuda` on the make command if needed. Set
`CUDA_VISIBLE_DEVICES=0` to select one GPU; the workload uses visible ordinal 0.
For a different utility path, build with `make` and run:

```bash
python3 run.py --cuda-checkpoint /path/to/cuda-checkpoint
```

The runner launches both peers under one fresh `cuda-checkpoint --launch-job`,
locks both peers, checkpoints them sequentially, then restores/unlocks them in
checkpoint order. It checks the CUDA state after every action and signals the
owner to validate the saved data and live IPC mapping. Success ends with:

```text
PASS: saved GPU contents and bidirectional IPC access verified after resume
```

Each run prints a fresh `/tmp/cuda-ipc-*` directory containing `actions.log` and
`workload.log`. Failed runs also save `failure.log`. Commands have a 30-second
outer timeout by default. On failure, the runner stops the disposable workload
without attempting CUDA rollback from an unknown state.

## Compare without the job wrapper

```bash
python3 run.py --no-launch-job --timeout 10
```

This also removes any inherited `CUDA_CHECKPOINT_JOB_FILE`. It uses the same real
IPC workload but omits the job identity required for supported IPC checkpointing.
Treat it as a negative control: it may fail, crash, or time out depending on the
driver. A hang is not guaranteed, and a CUDA CLI failure alone does not establish
the original CRIU/ptrace hang.

Local validation on an RTX 5090 Laptop GPU, driver/utility 610.57.04:

- With `--launch-job`: both peers completed all transitions and data validation.
- Without it: the first checkpoint command returned status 1 with
  `OS call failed or operation not supported on this OS`.

These results are CUDA-only. The CRIU dump reproducer below tests a separate
path involving ptrace and the plugin's Driver API calls.

## Reproduce the pre-worker CRIU hang

Checking out an older CRIU commit does not change the CUDA-only commands above.
Use `--criu` to invoke the built CRIU binary and plugin from the checkout:

```bash
# From test/others/cuda-ipc, with the checkout at ae54d1465:
make -C ../../.. -j"$(nproc)" cuda_plugin
make
sudo python3 ./run.py --criu --no-launch-job --timeout 10
```

This runs `criu dump --leave-running` with the Driver API backend. It does not
manually lock or checkpoint CUDA through the CLI. The default plugin path is
`plugins/cuda` in the same tree as the selected CRIU binary. To use another build:

```bash
sudo python3 ./run.py --criu /path/to/criu/criu/criu --no-launch-job --timeout 10
```

For a copied workload outside a CRIU checkout, pass the explicit binary path.
`--criu-libdir /path/to/plugins/cuda` can override the inferred plugin directory.
The CRIU log is saved as `images/dump.log` in the printed run directory.

On `ae54d1465`, a real run without the job wrapper timed out after ten seconds.
The dump log selected the Driver API backend, seized both IPC peers, and stopped
at `Checkpointing CUDA devices on pid ... restore_tid ...`, about 50 ms into the
dump. This establishes a hang in the real CUDA checkpoint path; that log alone
does not prove a SIGSEGV or identify the underlying driver fault.

Repeat on worker commit `ebd88ec7a` to compare failure handling. Since job identity
is still absent, the desired outcome is a prompt, diagnosed failure rather than
a successful dump. Omit `--no-launch-job` to test the supported job-scoped path.
The `--leave-running` test checks the plugin's dump-side GPU resume and workload
validation on success; it does not restore the saved CPU images.

## Use the workload independently

To control checkpointing yourself, launch the C program directly:

```bash
run_dir=$(mktemp -d /tmp/cuda-ipc-manual.XXXXXX)
cuda-checkpoint --launch-job ./cuda-ipc "$run_dir/ready"
```

It prints both PIDs and creates the ready file only after the first IPC exchange
passes. Both processes then wait with the allocation and imported mapping open.
The ready file contains `OWNER_PID IMPORTER_PID`. From another terminal, perform
the checkpoint/restore and send `kill -USR1 OWNER_PID` to validate and exit.
Omit the wrapper for the negative control, with `CUDA_CHECKPOINT_JOB_FILE` unset.

For CRIU tests, checkpoint the owner's process tree. Let CRIU's CUDA plugin own
the CUDA transitions; do not additionally run the CUDA-only runner on that same
workload. Send SIGUSR1 to the restored owner's host PID after CRIU restore.

The IPC job and ordered transitions follow NVIDIA's
[cuda-checkpoint documentation](https://github.com/NVIDIA/cuda-checkpoint#610-features).
