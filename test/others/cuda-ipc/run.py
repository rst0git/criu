#!/usr/bin/env python3
"""Run a real CUDA IPC round trip, with an optional missing-job negative control."""
import argparse
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--cuda-checkpoint", default="cuda-checkpoint")
    repo = Path(__file__).resolve().parents[3]
    parser.add_argument("--criu", nargs="?", const=str(repo / "criu/criu"),
                        help="test CRIU dump --leave-running using this binary (default: this checkout)")
    parser.add_argument("--criu-libdir",
                        help="CUDA plugin directory (default: plugins/cuda beside the CRIU source tree)")
    parser.add_argument("--no-launch-job", action="store_true",
                        help="negative control: do not create a CUDA checkpoint job")
    parser.add_argument("--timeout", type=float, default=30,
                        help="seconds allowed for each command and workload readiness")
    args = parser.parse_args()
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    work = Path(tempfile.mkdtemp(prefix="cuda-ipc-"))
    print(f"Logs: {work}", flush=True)
    env = os.environ.copy()
    env.pop("CUDA_CHECKPOINT_JOB_FILE", None)
    command = [str(Path(__file__).resolve().with_name("cuda-ipc")), str(work / "ready")]
    if not args.no_launch_job:
        command = [args.cuda_checkpoint, "--launch-job", *command]
    process = None
    success = False
    try:
        with (work / "workload.log").open("w") as workload_log, (work / "actions.log").open("w") as actions:
            process = subprocess.Popen(command, env=env, stdout=workload_log,
                                       stderr=subprocess.STDOUT, start_new_session=True)

            def run_command(cmd):
                print("+ " + " ".join(cmd), flush=True)
                actions.write("+ " + " ".join(cmd) + "\n")
                actions.flush()
                # Write directly to the log so a timed-out call retains its output.
                with tempfile.TemporaryFile(mode="w+") as output:
                    try:
                        result = subprocess.run(cmd, env=env, stdout=output,
                                                stderr=subprocess.STDOUT, timeout=args.timeout)
                    finally:
                        output.seek(0)
                        text = output.read()
                        actions.write(text)
                        actions.flush()
                if result.returncode:
                    raise RuntimeError(f"command failed ({result.returncode}): {' '.join(cmd)}\n{text}")
                return text.strip().lower()

            def cli(*options):
                return run_command([args.cuda_checkpoint, *map(str, options)])

            def state(pid, expected):
                actual = cli("--get-state", "--pid", pid)
                if actual != expected:
                    raise RuntimeError(f"PID {pid}: expected {expected}, got {actual!r}")

            deadline = time.monotonic() + args.timeout
            while True:
                if process.poll() is not None:
                    raise RuntimeError(f"workload exited before readiness ({process.returncode})")
                try:
                    pids = list(map(int, (work / "ready").read_text().split()))
                    if len(pids) == 2:
                        break
                except FileNotFoundError:
                    pass
                if time.monotonic() >= deadline:
                    raise TimeoutError("workload readiness timed out")
                time.sleep(0.05)

            for pid in pids:
                state(pid, "running")
            if args.criu:
                criu = Path(args.criu).resolve()
                libdir = (Path(args.criu_libdir).resolve() if args.criu_libdir
                          else criu.parent.parent / "plugins/cuda")
                images = work / "images"
                images.mkdir()
                run_command([
                    str(criu), "dump", "--no-default-config", "--tree", str(pids[0]),
                    "--images-dir", str(images), "--log-file", "dump.log", "-v4",
                    "--libdir", str(libdir), "--shell-job", "--leave-running",
                    "--timeout", "5", "--plugin-option=cuda_plugin.backend=driver-api",
                    f"--plugin-option=cuda_plugin.timeout={max(1, int(args.timeout / 2))}",
                ])
                # --leave-running exercises the plugin's dump-side CUDA resume.
                # This mode does not run CRIU restore of the saved CPU images.
                for pid in pids:
                    state(pid, "running")
            else:
                # Lock ALL peers before checkpointing ANY peer; never run in parallel.
                for pid in pids:
                    cli("--action", "lock", "--pid", pid, "--timeout", 5000)
                    state(pid, "locked")
                for pid in pids:
                    cli("--action", "checkpoint", "--pid", pid)
                    state(pid, "checkpointed")
                # Restore/unlock in the same order as checkpoint.
                for pid in pids:
                    cli("--action", "restore", "--pid", pid)
                    state(pid, "locked")
                    cli("--action", "unlock", "--pid", pid)
                    state(pid, "running")
            os.kill(pids[0], signal.SIGUSR1)
            if process.wait(timeout=args.timeout):
                raise RuntimeError(f"workload validation failed ({process.returncode})")
            if "PASS:" not in (work / "workload.log").read_text():
                raise RuntimeError("workload exited without completing validation")
        print((work / "workload.log").read_text(), end="")
        success = True
        return 0
    except (OSError, RuntimeError, subprocess.TimeoutExpired, TimeoutError) as error:
        detail = f"FAIL: {error}\n"
        if process is not None:
            status = process.poll()
            if status is not None:
                cause = signal.Signals(-status).name if status < 0 else str(status)
                detail += f"Workload exit before cleanup: {cause}\n"
        (work / "failure.log").write_text(detail)
        print(detail, end="", file=sys.stderr)
        print((work / "workload.log").read_text(), end="", file=sys.stderr)
        return 1
    finally:
        if process is not None:
            # These are only the disposable workload's own process-group members.
            # Do not attempt CUDA rollback after an unknown/partial driver failure.
            if not success:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            try:
                process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                print(f"Workload PID {process.pid} did not exit after SIGKILL", file=sys.stderr)


if __name__ == "__main__":
    sys.exit(main())
