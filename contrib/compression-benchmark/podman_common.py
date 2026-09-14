#!/usr/bin/env python3
"""Shared Podman serving checkpoint/restore benchmark implementation."""

import argparse
import base64
import contextlib
import errno
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import posixpath
import shlex
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request

# Sentinel distinguishing "runc.conf never touched" from "stashed, but the
# file did not exist" (which stashes None).
_RUNC_CONF_UNSET = object()


class RuntimeState:
    """Mutable resources owned by this benchmark process."""

    def __init__(self):
        self.tempdirs = set()
        self.started_containers = set()
        self.cleanup_containers = True
        self.original_runc_conf = _RUNC_CONF_UNSET
        self.runc_conf_lock_fd = None
        self.runc_conf_path = None
        self.runc_conf_state_path = None
        self.runc_conf_state = None
        self.criu_wrapper_dir = None
        self.cleanup_started = False
        self.received_signal = None
        self.trial_artifacts = None
        self.operation_outputs = {}


PODMAN = "podman"
RUNC_CONF_BEGIN = "# BEGIN criu-compression-benchmark"
RUNC_CONF_END = "# END criu-compression-benchmark"
PAGE_SIZE = os.sysconf("SC_PAGE_SIZE")
MAX_BLOCK_SIZE = 4 * 1024 * 1024
MAX_COMPRESSION_ACCELERATION = 65537
MAX_DECOMPRESSION_THREADS = 1024
COMPRESSION_OPTIONS = {
    "compress", "compress-block", "compress-acceleration",
    "decompress-threads",
}
HF_TOKEN_ENV_VARS = ("HF_TOKEN", "HUGGING_FACE_HUB_TOKEN")
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SIGNALS = (signal.SIGINT, signal.SIGHUP, signal.SIGTERM)


def default_block_sizes(page_size):
    candidates = (page_size, 64 * 1024, 256 * 1024, 1024 * 1024)
    return list(dict.fromkeys(
        size for size in candidates
        if size <= MAX_BLOCK_SIZE and size % page_size == 0
    ))


DEFAULT_BLOCK_SIZES = default_block_sizes(PAGE_SIZE)


class ServingBenchmark:
    """One framework driver with process-local mutable resource state."""

    def __init__(self, adapter, description):
        self.adapter = adapter
        self.description = description
        self.state = RuntimeState()

    def cleanup(self):
        return cleanup(self)

    def signal_handler(self, signum, frame):
        return signal_handler(self, signum, frame)

    def podman_env(self, args):
        return podman_env(self, args)

    def ensure_no_default_config_wrapper(self):
        return ensure_no_default_config_wrapper(self)

    def release_runc_conf_lock(self):
        return release_runc_conf_lock(self)

    def set_runc_conf_for_cfg(self, path, cfg, acceleration,
                              decompress_threads=None):
        return set_runc_conf_for_cfg(
            self, path, cfg, acceleration, decompress_threads
        )

    def restore_runc_conf(self):
        return restore_runc_conf(self)

    def build_container_cmd(self, name, args):
        return build_container_cmd(self, name, args)

    def start_container(self, name, args):
        return start_container(self, name, args)

    def checkpoint_container(self, name, archive, cfg, args):
        return checkpoint_container(self, name, archive, cfg, args)

    def restore_container(self, name, archive, args):
        return restore_container(self, name, archive, args)

    def chat_once(self, base_url, model, prompt, max_tokens, temperature,
                  seed, timeout, extra_body=None):
        return chat_once(
            base_url, model, prompt, max_tokens, temperature, seed, timeout,
            extra_body, self.adapter.display_name
        )

    def chat_stream_once(self, base_url, model, prompt, max_tokens,
                         temperature, seed, timeout, operation_started_ns,
                         extra_body=None):
        return chat_stream_once(
            base_url, model, prompt, max_tokens, temperature, seed, timeout,
            operation_started_ns, extra_body, self.adapter.display_name
        )

    def run_trial(self, cfg, workdir, args, trial_id, keep_running=False):
        return run_trial(self, cfg, workdir, args, trial_id, keep_running)

    def report(self, results_by_cfg, order):
        return report(self, results_by_cfg, order)

    def main(self, argv=None):
        return run_main(self, argv, self.description)


@contextlib.contextmanager
def _blocked_termination_signals():
    previous = signal.pthread_sigmask(signal.SIG_BLOCK, SIGNALS)
    try:
        yield
    finally:
        signal.pthread_sigmask(signal.SIG_SETMASK, previous)


def cleanup(benchmark):
    runtime = benchmark.state
    if runtime.cleanup_started:
        return
    with _blocked_termination_signals():
        runtime.cleanup_started = True
        try:
            restore_runc_conf(benchmark)
        except (OSError, RuntimeError, ValueError) as e:
            print(f"cleanup: failed to restore runc.conf: {e}", file=sys.stderr)
        if runtime.cleanup_containers:
            for name in list(runtime.started_containers):
                try:
                    result = subprocess.run([PODMAN, "rm", "-f", name],
                                            capture_output=True, text=True)
                except OSError as e:
                    print(f"cleanup: failed to execute Podman for {name}: {e}",
                          file=sys.stderr)
                    continue
                if result.returncode:
                    detail = (result.stderr or result.stdout).strip()
                    print(f"cleanup: failed to remove {name}: {detail[-1000:]}",
                          file=sys.stderr)
            runtime.started_containers.clear()
        for path in list(runtime.tempdirs):
            shutil.rmtree(path, ignore_errors=True)
            if os.path.exists(path):
                print(f"cleanup: failed to remove temporary directory {path}",
                      file=sys.stderr)
        runtime.tempdirs.clear()


def signal_handler(benchmark, signum, frame):
    runtime = benchmark.state
    if runtime.received_signal is not None:
        return
    runtime.received_signal = signum
    # Defer cleanup until the active command has stopped and Python starts
    # unwinding through atexit handlers.
    for handled in SIGNALS:
        signal.signal(handled, signal.SIG_IGN)
    raise SystemExit(128 + signum)


def median(v):
    s = sorted(v)
    n = len(s)
    if n == 0:
        return 0
    return s[n // 2] if n % 2 else (s[n // 2 - 1] + s[n // 2]) / 2


def format_bytes(byte_count):
    if byte_count >= 1073741824:
        return f"{byte_count / 1073741824:.2f} GB"
    return f"{byte_count / 1048576:.1f} MB"


def format_duration(microseconds):
    if microseconds >= 1e6:
        return f"{microseconds / 1e6:.3f} s"
    return f"{microseconds / 1000:.1f} ms"


def cfg_label(cfg):
    if cfg["mode"] == "uncompressed":
        label = "Uncompressed"
    else:
        label = f"LZ4 blocks ({cfg['block_size'] // 1024} KiB)"
    return f"{cfg['cuda_backend']} / {label}" if cfg.get("cuda_backend") else label


def decompress_threads_label(threads):
    """None uses CRIU's serial default; 0 is auto; positive values are explicit."""
    if threads is None:
        return "default (serial)"
    if threads == 0:
        return "auto"
    return str(threads)


def server_base_url(port, base_url):
    if base_url is not None:
        return base_url
    return f"http://127.0.0.1:{port}"


def json_object(value):
    try:
        obj = json.loads(value)
    except json.JSONDecodeError as e:
        raise argparse.ArgumentTypeError(str(e))
    if not isinstance(obj, dict):
        raise argparse.ArgumentTypeError("expected a JSON object")
    return obj


def cuda_benchmark_identity(args):
    """Identify the executable artifacts, including locally modified builds."""
    binaries = {"criu": shutil.which("criu"),
                "plugin": os.path.join(args.criu_libdir, "cuda_plugin.so")}
    if "cuda-checkpoint" in args.cuda_backends:
        binaries["cuda-checkpoint"] = shutil.which("cuda-checkpoint")
    if getattr(args, "cuda_checkpoint_launch_job", False):
        binaries["cuda-checkpoint-launcher"] = args.cuda_checkpoint_binary
    identity = {"binaries": {}}
    for name, path in binaries.items():
        if not path or not os.path.isfile(path):
            raise RuntimeError(f"CUDA comparison requires {name}: {path}")
        digest = hashlib.sha256()
        with open(path, "rb") as source:
            for chunk in iter(lambda: source.read(1024 * 1024), b""):
                digest.update(chunk)
        identity["binaries"][name] = {"path": os.path.realpath(path),
                                       "sha256": digest.hexdigest()}
    for name, command in (
        ("driver", ["nvidia-smi", "--query-gpu=uuid,name,driver_version",
                    "--format=csv,noheader"]),
        ("runc", ["runc", "--version"]),
    ):
        result = subprocess.run(command, capture_output=True, text=True,
                                check=True)
        identity[name] = result.stdout.strip()
    return identity


def collect_system_info():
    info = {"kernel": platform.release(), "arch": platform.machine(),
            "cpus": os.cpu_count()}
    try:
        with open("/proc/cpuinfo") as f:
            for line in f:
                if line.startswith("model name"):
                    info["cpu"] = line.split(":", 1)[1].strip()
                    break
    except OSError:
        info["cpu"] = "unknown"
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal"):
                    info["memory_mb"] = int(line.split()[1]) // 1024
                    break
    except OSError:
        info["memory_mb"] = 0
    for cmd, key in (([PODMAN, "--version"], "podman"),
                     (["criu", "--version"], "criu")):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode == 0:
                info[key] = r.stdout.strip()
        except OSError:
            info[key] = "unknown"
    try:
        r = subprocess.run(["nvidia-smi", "--query-gpu=name",
                            "--format=csv,noheader"],
                           capture_output=True, text=True)
        if r.returncode == 0:
            info["gpus"] = [line.strip() for line in r.stdout.splitlines()
                            if line.strip()]
    except OSError:
        info["gpus"] = []
    return info


def http_json(method, url, payload=None, timeout=120):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload).encode()
        headers["Content-Type"] = "application/json"
        headers["Authorization"] = "Bearer EMPTY"
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        body = resp.read()
    return json.loads(body.decode()) if body else {}


def podman_text(args):
    try:
        r = subprocess.run([PODMAN, *args], capture_output=True, text=True)
    except OSError as e:
        return f"unable to execute Podman: {e}"
    return (r.stdout + r.stderr).strip()


def container_diagnostics(name):
    parts = [f"container={name}"]
    ps = podman_text(["ps", "-a", "--filter", f"name=^{name}$",
                      "--format", "{{.Names}} {{.Status}} {{.Ports}}"])
    if ps:
        parts.append(f"podman ps:\n{ps}")
    logs = podman_text(["logs", "--tail", "80", name])
    if logs:
        parts.append(f"last logs:\n{logs[-6000:]}")
    return "\n\n".join(parts)


def container_exit_code(name):
    """Return an exit code for a stopped container, or None otherwise."""
    try:
        result = subprocess.run(
            [PODMAN, "inspect", "--format",
             "{{.State.Running}} {{.State.ExitCode}}", name],
            capture_output=True, text=True,
        )
    except OSError:
        return None
    if result.returncode:
        return None
    fields = result.stdout.strip().split()
    if len(fields) != 2 or fields[0].lower() != "false":
        return None
    try:
        return int(fields[1])
    except ValueError:
        return None


def wait_health(base_url, health_path, timeout, container_name=None,
                framework_name="serving"):
    deadline = time.monotonic() + timeout
    next_state_check = 0
    last = None
    url = f"{base_url.rstrip('/')}/{health_path.lstrip('/')}"
    while time.monotonic() < deadline:
        try:
            urllib.request.urlopen(url, timeout=5).read()
            return
        except (OSError, urllib.error.URLError) as e:
            last = e
            now = time.monotonic()
            if container_name and now >= next_state_check:
                next_state_check = now + 5
                exit_code = container_exit_code(container_name)
                if exit_code is not None:
                    raise RuntimeError(
                        f"{framework_name} container exited with status {exit_code} "
                        f"before becoming healthy\n\n"
                        f"{container_diagnostics(container_name)}"
                    ) from e
            time.sleep(0.1)
    detail = ""
    if container_name:
        detail = "\n\n" + container_diagnostics(container_name)
    raise RuntimeError(
        f"{framework_name} health check timed out after {timeout}s: {last}{detail}"
    )


def chat_once(base_url, model, prompt, max_tokens, temperature, seed, timeout,
              extra_body=None, framework_name="serving"):
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "seed": seed,
    }
    if extra_body:
        payload.update(extra_body)
    t0 = time.monotonic()
    data = http_json("POST", f"{base_url.rstrip('/')}/v1/chat/completions",
                     payload, timeout)
    latency_us = int((time.monotonic() - t0) * 1e6)
    content = data.get("choices", [{}])[0].get("message", {}).get("content", "")
    if not content.strip():
        raise RuntimeError(f"{framework_name} validation returned an empty response")
    return latency_us, content


def chat_stream_once(base_url, model, prompt, max_tokens, temperature, seed,
                     timeout, operation_started_ns, extra_body=None,
                     framework_name="serving"):
    """Issue one streaming chat request and timestamp its readiness events.

    Absolute offsets are measured from ``operation_started_ns`` so cold start
    and restore use the same boundary. Request latency is also returned to
    distinguish serving time from startup/restore time.
    """
    payload = {
        "model": model,
        "messages": [{"role": "user", "content": prompt}],
        "temperature": temperature,
        "max_tokens": max_tokens,
        "seed": seed,
        "stream": True,
        "stream_options": {"include_usage": True},
    }
    if extra_body:
        payload.update(extra_body)
    data = json.dumps(payload).encode()
    request = urllib.request.Request(
        f"{base_url.rstrip('/')}/v1/chat/completions",
        data=data,
        headers={
            "Content-Type": "application/json",
            "Authorization": "Bearer EMPTY",
        },
        method="POST",
    )
    request_started_ns = time.monotonic_ns()
    first_event_ns = None
    first_token_ns = None
    chunks = []
    output_chunks = []
    reasoning_chunks = []
    finish_reason = None
    usage = None
    completed = False
    with urllib.request.urlopen(request, timeout=timeout) as response:
        response_headers_ns = time.monotonic_ns()
        for raw_line in response:
            line = raw_line.decode(errors="replace").strip()
            if not line.startswith("data:"):
                continue
            now_ns = time.monotonic_ns()
            if first_event_ns is None:
                first_event_ns = now_ns
            event = line[5:].strip()
            if event == "[DONE]":
                completed = True
                break
            try:
                document = json.loads(event)
            except json.JSONDecodeError as error:
                raise RuntimeError(
                    f"{framework_name} returned malformed streaming JSON: "
                    f"{event[:200]}"
                ) from error
            if not isinstance(document, dict):
                raise RuntimeError(f"{framework_name} returned a non-object streaming event")
            if "error" in document:
                raise RuntimeError(
                    f"{framework_name} streaming request failed: {document['error']}")
            if document.get("usage") is not None:
                usage = document["usage"]
                if not isinstance(usage, dict):
                    raise RuntimeError(f"{framework_name} returned invalid token usage")
            # OpenAI-compatible servers send usage in a final choices=[] event.
            choices = document.get("choices", [])
            if not isinstance(choices, list):
                raise RuntimeError(f"{framework_name} returned invalid streaming choices")
            for choice in choices:
                if not isinstance(choice, dict):
                    raise RuntimeError(f"{framework_name} returned an invalid streaming choice")
                if choice.get("index", 0) != 0:
                    continue
                delta = choice.get("delta") or {}
                if not isinstance(delta, dict):
                    raise RuntimeError(f"{framework_name} returned an invalid streaming delta")
                for field, target in (("reasoning_content", reasoning_chunks),
                                      ("content", output_chunks)):
                    text = delta.get(field)
                    if text is None:
                        continue
                    if not isinstance(text, str):
                        raise RuntimeError(
                            f"{framework_name} returned non-text {field}")
                    if text:
                        if first_token_ns is None:
                            first_token_ns = now_ns
                        chunks.append(text)
                        target.append(text)
                if choice.get("finish_reason") is not None:
                    finish_reason = choice["finish_reason"]
                    if finish_reason not in ("stop", "length"):
                        raise RuntimeError(
                            f"{framework_name} streaming request ended with "
                            f"finish_reason={finish_reason!r}")
    completed_ns = time.monotonic_ns()
    content = "".join(chunks)
    output_content = "".join(output_chunks)
    if not completed or finish_reason is None:
        raise RuntimeError(
            f"{framework_name} streaming response was incomplete: "
            f"received_done={completed}, finish_reason={finish_reason!r}")
    if first_token_ns is None or not output_content.strip():
        raise RuntimeError(
            f"{framework_name} streaming validation returned no final output text"
        )

    def elapsed_us(end_ns, start_ns):
        return (end_ns - start_ns) // 1000

    return {
        "request_us": elapsed_us(completed_ns, request_started_ns),
        "request_to_headers_us": elapsed_us(
            response_headers_ns, request_started_ns
        ),
        "request_to_first_event_us": elapsed_us(
            first_event_ns, request_started_ns
        ),
        "request_to_first_token_us": elapsed_us(
            first_token_ns, request_started_ns
        ),
        "operation_to_request_us": elapsed_us(
            request_started_ns, operation_started_ns
        ),
        "operation_to_headers_us": elapsed_us(
            response_headers_ns, operation_started_ns
        ),
        "operation_to_first_event_us": elapsed_us(
            first_event_ns, operation_started_ns
        ),
        "operation_to_first_token_us": elapsed_us(
            first_token_ns, operation_started_ns
        ),
        "operation_to_response_complete_us": elapsed_us(
            completed_ns, operation_started_ns
        ),
        "content": content,
        "output_content": output_content,
        "reasoning_content": "".join(reasoning_chunks),
        "finish_reason": finish_reason,
        "usage": usage,
        "completed": completed,
    }


def format_cmd(cmd):
    """Format a command without printing values passed through --env."""
    out = []
    redact_next = False
    for item in cmd:
        if redact_next:
            name = item.split("=", 1)[0]
            out.append(f"{name}=<redacted>" if "=" in item else item)
            redact_next = False
            continue
        if item.startswith("--env=") or (item.startswith("-e") and
                                           not item.startswith("--")):
            if item.startswith("--env="):
                option, value = item.split("=", 1)
            else:
                option, value = "-e", item[2:].lstrip("=")
            name = value.split("=", 1)[0]
            out.append(f"{option}{'=' if option == '--env' else ''}"
                       f"{name}=<redacted>" if "=" in value
                       else item)
            continue
        out.append(item)
        redact_next = item in ("--env", "-e")
    return " ".join(out)


def run_arg_sets_environment(item):
    """Return whether a raw Podman argument can carry an environment value."""
    return (item == "--env" or item.startswith("--env=") or
            (item.startswith("-e") and not item.startswith("--")))


def redact_run_arg(item):
    if item.startswith("--env=") or (item.startswith("-e") and
                                       not item.startswith("--")):
        if item.startswith("--env="):
            option, value = item.split("=", 1)
        else:
            option, value = "-e", item[2:].lstrip("=")
        name = value.split("=", 1)[0]
        separator = "=" if option == "--env" else ""
        return f"{option}{separator}{name}=<redacted>" if "=" in value else item
    return item


def redact_run_args(items):
    out = []
    redact_next = False
    for item in items:
        if redact_next:
            name = item.split("=", 1)[0]
            out.append(f"{name}=<redacted>" if "=" in item else item)
            redact_next = False
            continue
        out.append(redact_run_arg(item))
        redact_next = item in ("--env", "-e")
    return out


def run_cmd(cmd, env=None, check=True, timeout=None, progress=None):
    try:
        if timeout is None and progress is None:
            r = subprocess.run(cmd, capture_output=True, text=True, env=env)
        else:
            started = time.monotonic()
            with subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, env=env, start_new_session=True) as process:
                try:
                    while True:
                        remaining = timeout - (time.monotonic() - started) if timeout is not None else 30
                        if remaining <= 0:
                            raise subprocess.TimeoutExpired(cmd, timeout)
                        try:
                            stdout, stderr = process.communicate(timeout=min(30, remaining))
                            break
                        except subprocess.TimeoutExpired:
                            if progress:
                                print(f"  {progress}: {time.monotonic() - started:.0f}s elapsed",
                                      flush=True)
                except BaseException as error:
                    # The runtime/CRIU children inherit these pipes. Killing
                    # only Podman can leave communicate waiting indefinitely.
                    try:
                        os.killpg(process.pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        stdout, stderr = process.communicate(timeout=5)
                    except subprocess.TimeoutExpired as drain_error:
                        # A descendant may have changed session. Preserve the
                        # captured output without waiting for its pipe EOF.
                        stdout, stderr = drain_error.output, drain_error.stderr
                        process.stdout.close()
                        process.stderr.close()
                    error.output = stdout.decode(errors="replace") if isinstance(stdout, bytes) else stdout or ""
                    error.stderr = stderr.decode(errors="replace") if isinstance(stderr, bytes) else stderr or ""
                    raise
            r = subprocess.CompletedProcess(cmd, process.returncode, stdout, stderr)
    except OSError as e:
        raise RuntimeError(f"unable to execute {format_cmd(cmd)}: {e}") from e
    if check and r.returncode:
        msg = (r.stderr or r.stdout).strip()
        raise RuntimeError(f"{format_cmd(cmd)} failed: {msg[-6000:]}")
    return r


def prepare_trial(benchmark, workdir, args, trial_id):
    destination = Path(getattr(args, "artifacts_dir", None) or workdir) / f"trial-{trial_id}"
    destination.mkdir()
    benchmark.state.trial_artifacts = destination
    benchmark.state.operation_outputs = {}
    print(f"  Trial {trial_id} artifacts: {destination}", flush=True)
    return destination


def write_json(path, value):
    temporary = Path(str(path) + ".tmp")
    temporary.write_text(json.dumps(value, indent=2) + "\n")
    temporary.replace(path)


@contextlib.contextmanager
def trial_phase(benchmark, phase):
    """Persist the last phase even if a process is interrupted or loses stdout."""
    destination = benchmark.state.trial_artifacts
    started = time.monotonic_ns()
    progress = {"phase": phase, "status": "running"}
    if destination:
        write_json(destination / "progress.json", progress)
    print(f"  {phase}", flush=True)
    try:
        yield
    except BaseException as error:
        progress.update(status="failed", error=str(error) or type(error).__name__)
        raise
    else:
        progress["status"] = "complete"
    finally:
        progress["elapsed_us"] = (time.monotonic_ns() - started) // 1000
        if destination:
            try:
                write_json(destination / "progress.json", progress)
            except OSError:
                if progress["status"] != "failed":
                    raise
                print(f"Unable to save {phase} failure progress", file=sys.stderr)


def inspect_container(name):
    result = run_cmd([PODMAN, "container", "inspect", name])
    try:
        entries = json.loads(result.stdout)
        if not isinstance(entries, list) or len(entries) != 1 or not isinstance(entries[0], dict):
            raise ValueError("expected one container")
        return entries[0]
    except (ValueError, TypeError) as error:
        raise RuntimeError(f"Unable to inspect benchmark container {name}: {error}") from error


def checkpoint_directory(name):
    info = inspect_container(name)
    path = info.get("State", {}).get("CheckpointPath")
    if not path or not Path(path).is_dir():
        raise RuntimeError(f"Container {name} has no checkpoint directory: {path}")
    return Path(path)


def save_container_artifacts(benchmark, name, phase, required=True):
    """Copy small diagnostics before Podman cleanup; never copy model memory here."""
    if benchmark.state.trial_artifacts is None:
        return
    destination = benchmark.state.trial_artifacts / phase
    destination.mkdir(exist_ok=True)
    result = benchmark.state.operation_outputs.get(phase)
    if result:
        (destination / "podman.stdout").write_text(result.stdout)
        (destination / "podman.stderr").write_text(result.stderr)
    info = inspect_container(name)
    state = info.get("State", {})
    write_json(destination / "container-state.json", {
        "id": info.get("Id"), "state": {
            key: state.get(key) for key in
            ("Status", "Pid", "ExitCode", "Checkpointed", "Restored")
        },
    })
    log_name, stats_name, log_key = (("dump.log", "stats-dump", "CheckpointLog")
                                     if phase == "checkpoint"
                                     else ("restore.log", "stats-restore", "RestoreLog"))
    if state.get(log_key):
        log_path = Path(state[log_key])
    elif info.get("OCIConfigPath"):
        log_path = Path(info["OCIConfigPath"]).parent / log_name
    else:
        # Older inspect responses may not expose the operation's log path.
        log_path = Path(info["StaticDir"]) / log_name
    for filename, source in ((log_name, log_path), (stats_name, log_path.parent / stats_name)):
        if source.is_file():
            shutil.copy2(source, destination / filename)
        elif required:
            raise RuntimeError(f"Missing {phase} diagnostic: {source}")


def podman_operation(benchmark, name, cmd, phase, args):
    """Time the command, then preserve its output and CRIU diagnostics."""
    environment = podman_env(benchmark, args)
    destination = benchmark.state.trial_artifacts
    if destination:
        destination = destination / phase
        destination.mkdir(exist_ok=True)
    started = time.monotonic_ns()
    try:
        result = run_cmd(cmd, env=environment, check=False,
                         timeout=getattr(args, "command_timeout", 3600), progress=phase)
        elapsed_us = (time.monotonic_ns() - started) // 1000
        benchmark.state.operation_outputs[phase] = result
        if result.returncode:
            raise RuntimeError(f"{format_cmd(cmd)} failed: "
                               f"{(result.stderr or result.stdout).strip()[-6000:]}")
    except BaseException as error:
        if hasattr(error, "output"):
            benchmark.state.operation_outputs[phase] = subprocess.CompletedProcess(
                cmd, -1, error.output or "", error.stderr or "")
        try:
            save_container_artifacts(benchmark, name, phase, required=False)
        except (OSError, RuntimeError, KeyError, TypeError) as error:
            print(f"Unable to save {phase} diagnostics: {error}", file=sys.stderr)
        raise
    return elapsed_us, result.stdout.strip()


def inspect_checkpoint(benchmark, name, archive, cfg, args):
    storage = getattr(args, "checkpoint_storage", "archive")
    source = checkpoint_directory(name) if storage == "local" else Path(archive)
    mode = verify_archive_compression(source, cfg)
    paths = list(source.rglob("*")) if source.is_dir() else [source]
    files = [path.stat() for path in paths if path.is_file()]
    size = sum(item.st_size for item in files)
    save_container_artifacts(benchmark, name, "checkpoint")
    return {
        "checkpoint_storage": storage,
        "checkpoint_size": size,
        "checkpoint_size_scope": "criu_images" if storage == "local" else "podman_archive",
        "checkpoint_disk_bytes": sum(item.st_blocks * 512 for item in files),
        "archive_size": size if storage == "archive" else None,
        "inventory_compress_mode": mode,
    }


def retain_checkpoint(benchmark, name, archive, args):
    if not getattr(args, "keep_checkpoint_files", False):
        return
    destination = benchmark.state.trial_artifacts / "checkpoint"
    if getattr(args, "checkpoint_storage", "archive") == "archive":
        shutil.move(archive, destination / Path(archive).name)
    else:
        source = checkpoint_directory(name)
        # This optional copy is outside all measured intervals. Preserve sparse
        # images and use a reflink when the filesystem supports it.
        run_cmd(["cp", "-a", "--reflink=auto", "--sparse=always",
                 str(source), str(destination / "images")])


def host_state(path, accelerator):
    """Cheap phase-boundary observations; they are not continuous profiling."""
    result = {"memory": {}}
    for line in Path("/proc/meminfo").read_text().splitlines():
        key, value = line.split(":", 1)
        if key in ("MemAvailable", "Cached", "Dirty", "Writeback", "SwapFree"):
            result["memory"][key + "_kib"] = int(value.split()[0])
    usage = shutil.disk_usage(path)
    result["storage"] = {"path": str(path), "device": os.stat(path).st_dev,
                         "free_bytes": usage.free, "total_bytes": usage.total}
    mount = run_cmd(["findmnt", "--json", "--target", str(path),
                     "--output", "SOURCE,FSTYPE,TARGET,OPTIONS"], check=False)
    result["storage"]["mount"] = json.loads(mount.stdout) if mount.returncode == 0 else None
    if accelerator == "gpu":
        gpu = run_cmd(["nvidia-smi", "--query-gpu=uuid,memory.used,utilization.gpu",
                       "--format=csv,noheader,nounits"])
        result["gpu_columns"] = ["uuid", "memory_used_mib", "utilization_percent"]
        result["gpu"] = gpu.stdout.strip().splitlines()
    return result


def checkpoint_storage_path(name, workdir, args):
    if getattr(args, "checkpoint_storage", "archive") == "local":
        # CRIU images are under Podman's bundle, which can be on a different
        # filesystem from both StaticDir (transient storage) and workdir.
        info = inspect_container(name)
        state = info.get("State", {})
        if state.get("CheckpointPath"):
            return Path(state["CheckpointPath"]).parent
        if info.get("OCIConfigPath"):
            # Available before the first checkpoint, unlike CheckpointPath.
            return Path(info["OCIConfigPath"]).parent
        for key in ("CheckpointLog", "RestoreLog"):
            if state.get(key):
                return Path(state[key]).parent
        return Path(info["StaticDir"])
    return Path(workdir)


def condition_restore_cache(benchmark, name, archive, args):
    policy = getattr(args, "cache_policy", "uncontrolled")
    if policy == "cold":
        # Explicit opt-in: affects the entire host. Never include synchronization
        # and eviction in the restore timer.
        run_cmd(["sync"])
        Path("/proc/sys/vm/drop_caches").write_text("3\n")
    return policy


def observe_host(benchmark, label, path, args):
    if not getattr(args, "artifacts_dir", None):
        return
    write_json(benchmark.state.trial_artifacts / f"host-{label}.json",
               host_state(path, getattr(args, "accelerator", "cpu")))


def remove_container(name, attempts=3, retry_delay=1):
    """Remove a container, tolerating a runtime's delayed PID-1 exit.

    Restored SGLang containers can finish their graceful shutdown just after
    Podman's force-removal timeout. A subsequent removal succeeds once the
    runtime has reaped PID 1, so do not turn that transient race into a failed
    benchmark trial. Persistent failures still raise with Podman's final
    diagnostic.
    """
    last = None
    for attempt in range(attempts):
        last = run_cmd([PODMAN, "rm", "-f", name], check=False)
        if last.returncode == 0:
            return
        if attempt + 1 < attempts:
            time.sleep(retry_delay)
    detail = (last.stderr or last.stdout).strip()
    raise RuntimeError(
        f"{format_cmd([PODMAN, 'rm', '-f', name])} failed after "
        f"{attempts} attempts: {detail[-6000:]}"
    )


def podman_env(benchmark, args):
    env = os.environ.copy()
    # Start CRIU without global, user, or inherited configuration. runc still
    # supplies the benchmark-owned runc.conf through the RPC request.
    env.pop("CRIU_CONFIG_FILE", None)
    wrapper_dir = benchmark.ensure_no_default_config_wrapper()
    env["PATH"] = wrapper_dir + os.pathsep + env.get("PATH", os.defpath)
    if args.criu_libdir:
        env["CRIU_LIBS_DIR"] = args.criu_libdir
    return env


def ensure_no_default_config_wrapper(benchmark):
    runtime = benchmark.state
    if runtime.criu_wrapper_dir is not None:
        return runtime.criu_wrapper_dir
    criu = shutil.which("criu")
    if criu is None:
        raise RuntimeError("criu was not found in PATH")
    wrapper_dir = tempfile.mkdtemp(prefix="criu-no-default-config-")
    runtime.tempdirs.add(wrapper_dir)
    wrapper = os.path.join(wrapper_dir, "criu")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(wrapper, flags, 0o700)
    try:
        with os.fdopen(fd, "w") as output:
            fd = -1
            output.write("#!/bin/sh\n")
            output.write(f"exec {shlex.quote(criu)} --no-default-config \"$@\"\n")
    finally:
        if fd >= 0:
            os.close(fd)
    runtime.criu_wrapper_dir = wrapper_dir
    return wrapper_dir


def read_file(path):
    try:
        with open(path) as f:
            return f.read()
    except FileNotFoundError:
        return None


def _sync_directory(path):
    directory = os.path.dirname(path) or "."
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _read_xattrs(path):
    if not hasattr(os, "listxattr"):
        return None
    try:
        names = os.listxattr(path)
    except OSError as e:
        if e.errno in (errno.ENOTSUP, errno.ENOSYS):
            return None
        raise
    return {
        name: base64.b64encode(os.getxattr(path, name)).decode("ascii")
        for name in names
    }


def _apply_xattrs(path, encoded):
    if encoded is None:
        return
    current = _read_xattrs(path)
    if current is None:
        if encoded:
            raise OSError(errno.ENOTSUP, "extended attributes are unsupported",
                          path)
        return
    for name in current.keys() - encoded.keys():
        os.removexattr(path, name)
    for name, value in encoded.items():
        decoded = base64.b64decode(value, validate=True)
        if current.get(name) != value:
            os.setxattr(path, name, decoded)


def _apply_metadata(path, metadata):
    current = os.stat(path)
    if current.st_uid != metadata["uid"] or current.st_gid != metadata["gid"]:
        os.chown(path, metadata["uid"], metadata["gid"])
    os.chmod(path, metadata["mode"])
    _apply_xattrs(path, metadata.get("xattrs"))
    os.utime(path, ns=(metadata["atime_ns"], metadata["mtime_ns"]))


def write_file(path, data, metadata=None):
    directory = os.path.dirname(path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}.{time.monotonic_ns()}"
    if metadata is None:
        metadata = _runc_conf_metadata(path)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w") as f:
            fd = -1
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
            if metadata is not None:
                _apply_metadata(tmp, metadata)
                os.fsync(f.fileno())
        os.replace(tmp, path)
        _sync_directory(path)
    finally:
        if fd >= 0:
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def _runc_conf_metadata(path):
    try:
        metadata = os.stat(path)
    except FileNotFoundError:
        return None
    return {
        "mode": stat.S_IMODE(metadata.st_mode),
        "uid": metadata.st_uid,
        "gid": metadata.st_gid,
        "atime_ns": metadata.st_atime_ns,
        "mtime_ns": metadata.st_mtime_ns,
        "xattrs": _read_xattrs(path),
    }


def _file_state(path):
    # Capture timestamps before opening the file: reading an old file can
    # update its atime under relatime.
    metadata = _runc_conf_metadata(path)
    content = read_file(path) if metadata is not None else None
    return {
        "existed": content is not None,
        "content": content,
        "metadata": metadata,
    }


def _metadata_identity(metadata):
    if metadata is None:
        return None
    return {key: metadata.get(key) for key in
            ("mode", "uid", "gid", "mtime_ns", "xattrs")}


def _same_file_state(actual, expected):
    if actual["existed"] != expected["existed"]:
        return False
    if not actual["existed"]:
        return True
    if actual["content"] != expected["content"]:
        return False
    # Metadata for a newly created pending file is not known until after its
    # atomic rename. Content still makes that narrow recovery window safe.
    if expected.get("metadata") is None:
        return True
    return (_metadata_identity(actual["metadata"]) ==
            _metadata_identity(expected["metadata"]))


def _owned_runc_conf_state(state):
    current = _file_state(state["path"])
    owned = [state["active"]]
    if state.get("pending") is not None:
        owned.append(state["pending"])
    if not any(_same_file_state(current, item) for item in owned):
        raise RuntimeError(
            f"{state['path']} changed outside the compression benchmark; "
            "refusing to overwrite it (recovery state was preserved)"
        )
    return current


def _restore_runc_conf_state(state, state_path):
    _owned_runc_conf_state(state)
    path = state["path"]
    original = state["original"]
    # Journal the restore before changing the target. If the process dies
    # after the rename/unlink but before removing the journal, the next run
    # can recognize the original file as benchmark-owned recovery work.
    state["pending"] = original
    _write_recovery_state(state_path, state)
    if original["existed"]:
        write_file(path, original["content"], original["metadata"])
    else:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(path)
        _sync_directory(path)


def _write_recovery_state(path, state):
    tmp = f"{path}.tmp.{os.getpid()}.{time.monotonic_ns()}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "w") as output:
            fd = -1
            json.dump(state, output)
            output.flush()
            os.fsync(output.fileno())
        os.replace(tmp, path)
        _sync_directory(path)
    finally:
        if fd >= 0:
            os.close(fd)
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)


def _read_recovery_state(path):
    flags = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags)
    with os.fdopen(fd) as source:
        metadata = os.fstat(source.fileno())
        if not stat.S_ISREG(metadata.st_mode):
            raise RuntimeError(f"invalid runc.conf recovery file: {path}")
        state = json.load(source)
    if (not isinstance(state, dict) or
            not all(key in state for key in ("path", "original", "active"))):
        raise RuntimeError(f"invalid runc.conf recovery file: {path}")
    return state


def acquire_runc_conf(benchmark, path):
    runtime = benchmark.state
    # Every spelling of the same target, including symlink aliases, must use
    # one lock and one recovery journal.
    target = os.path.realpath(path)
    lock_path = target + ".compression-benchmark.lock"
    directory = os.path.dirname(lock_path)
    if directory:
        os.makedirs(directory, exist_ok=True)
    flags = os.O_RDWR | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    lock_fd = os.open(lock_path, flags, 0o600)
    try:
        try:
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError as exc:
            raise RuntimeError(
                f"another compression benchmark is using {path}"
            ) from exc

        state_path = lock_path + ".state"
        if os.path.exists(state_path):
            state = _read_recovery_state(state_path)
            if state.get("path") != target:
                raise RuntimeError(
                    f"runc.conf recovery state refers to {state.get('path')}, "
                    f"not {target}"
                )
            _restore_runc_conf_state(state, state_path)
            os.unlink(state_path)
            _sync_directory(state_path)

        original = _file_state(target)
        state = {
            "path": target,
            "original": original,
            "active": original,
            "pending": None,
        }
        _write_recovery_state(state_path, state)
        runtime.runc_conf_lock_fd = lock_fd
        runtime.runc_conf_path = target
        runtime.runc_conf_state_path = state_path
        runtime.runc_conf_state = state
        return target, original["content"]
    except BaseException:
        os.close(lock_fd)
        raise


def release_runc_conf_lock(benchmark):
    runtime = benchmark.state
    if runtime.runc_conf_lock_fd is not None:
        fcntl.flock(runtime.runc_conf_lock_fd, fcntl.LOCK_UN)
        os.close(runtime.runc_conf_lock_fd)
    runtime.runc_conf_lock_fd = None
    runtime.runc_conf_path = None
    runtime.runc_conf_state_path = None
    runtime.runc_conf_state = None


def strip_compression_runc_options(text):
    """Remove prior benchmark blocks and any ambient compression options."""
    if not text:
        return ""
    lines = text.splitlines()
    out = []
    skipping = False
    for line in lines:
        if line.strip() == RUNC_CONF_BEGIN:
            skipping = True
            continue
        if line.strip() == RUNC_CONF_END:
            skipping = False
            continue
        if skipping:
            continue
        statement = line.strip()
        if not statement or statement.startswith("#"):
            out.append(line)
            continue
        option = statement.split(None, 1)[0].split("=", 1)[0]
        option = option.lstrip("-").replace("_", "-")
        if option not in COMPRESSION_OPTIONS:
            out.append(line)
    return "\n".join(out).rstrip()


def compression_config_lines(cfg, acceleration, decompress_threads=None):
    if cfg["mode"] == "uncompressed":
        return []
    lines = [f"compress-block {cfg['block_size']}"]
    if acceleration != 1:
        lines.append(f"compress-acceleration {acceleration}")
    if decompress_threads is not None:
        lines.append(f"decompress-threads {decompress_threads}")
    return lines


def cuda_backend_config_base(base):
    """Replace only options owned by a CUDA backend comparison."""
    kept = []
    for line in base.splitlines():
        fields = shlex.split(line, comments=True)
        if fields:
            option, _, inline = fields[0].lstrip("-").partition("=")
            value = inline or (fields[1] if len(fields) > 1 else "")
            if option in ("libdir", "verbosity") or (option == "plugin-option" and
                    value.startswith(("cuda_plugin.backend=", "cuda_plugin.timings="))):
                continue
        kept.append(line)
    return "\n".join(kept)


def set_runc_conf_for_cfg(benchmark, path, cfg, acceleration,
                          decompress_threads=None):
    runtime = benchmark.state
    if runtime.original_runc_conf is _RUNC_CONF_UNSET:
        path, original = acquire_runc_conf(benchmark, path)
        runtime.original_runc_conf = original
    else:
        path = runtime.runc_conf_path

    base = strip_compression_runc_options(runtime.original_runc_conf)
    lines = compression_config_lines(cfg, acceleration, decompress_threads)
    if cfg.get("cuda_backend"):
        base = cuda_backend_config_base(base)
        lines += [f"libdir {json.dumps(cfg['criu_libdir'])}",
                  f"plugin-option cuda_plugin.backend={cfg['cuda_backend']}",
                  f"plugin-option cuda_plugin.timings={'true' if cfg.get('cuda_timings') else 'false'}",
                  "verbosity 4"]
    if lines:
        block = "\n".join([RUNC_CONF_BEGIN, *lines, RUNC_CONF_END])
        text = f"{base}\n\n{block}\n" if base else f"{block}\n"
    else:
        text = f"{base}\n" if base else ""
    current = _owned_runc_conf_state(runtime.runc_conf_state)
    runtime.runc_conf_state["pending"] = {
        "existed": True,
        "content": text,
        "metadata": current["metadata"],
    }
    _write_recovery_state(runtime.runc_conf_state_path,
                          runtime.runc_conf_state)
    write_file(path, text, current["metadata"])
    runtime.runc_conf_state["active"] = _file_state(path)
    runtime.runc_conf_state["pending"] = None
    _write_recovery_state(runtime.runc_conf_state_path,
                          runtime.runc_conf_state)


def restore_runc_conf(benchmark):
    runtime = benchmark.state
    if runtime.original_runc_conf is _RUNC_CONF_UNSET:
        return
    path = runtime.runc_conf_path
    if not path:
        return
    with _blocked_termination_signals():
        try:
            _restore_runc_conf_state(runtime.runc_conf_state,
                                     runtime.runc_conf_state_path)
            if runtime.runc_conf_state_path is not None:
                os.unlink(runtime.runc_conf_state_path)
                _sync_directory(runtime.runc_conf_state_path)
        finally:
            runtime.original_runc_conf = _RUNC_CONF_UNSET
            release_runc_conf_lock(benchmark)


def build_container_cmd(benchmark, name, args):
    cmd = [
        PODMAN, "run", "-d",
        "--name", name,
        "--security-opt", args.security_opt,
        "--network", "host",
        "--shm-size", args.shm_size,
        "-v", f"{args.hf_cache}:/root/.cache/huggingface",
    ]
    for name in HF_TOKEN_ENV_VARS:
        # Podman copies the value from its environment. It never appears in
        # this process's command line or in an error message.
        if name in os.environ:
            cmd += ["--env", name]
    if args.accelerator == "gpu":
        cmd += [
            "--device", args.gpu_device,
            "--env", f"CUDA_VISIBLE_DEVICES={args.cuda_visible_devices}",
            "--env", "NCCL_P2P_DISABLE=1",
            "--env", "NCCL_SHM_DISABLE=1",
            "--env", "NCCL_IB_DISABLE=1",
            "--env", "NCCL_CUMEM_ENABLE=0",
        ]
    else:
        cmd += benchmark.adapter.cpu_podman_args(args)
    for item in args.env:
        cmd += ["--env", item]
    if getattr(args, "offline", False):
        cmd += ["--env", "HF_HUB_OFFLINE=1", "--env", "TRANSFORMERS_OFFLINE=1"]
    for item in args.volume:
        cmd += ["-v", item]
    for item in args.run_arg:
        cmd.append(item)
    for item in args.ulimit:
        cmd += ["--ulimit", item]
    extra_podman_args = getattr(benchmark.adapter, "extra_podman_args", None)
    if extra_podman_args is not None:
        cmd += extra_podman_args(args)

    cmd += benchmark.adapter.server_argv(args)

    return cmd


def ensure_server_port_available(port):
    # The containers use host networking and bind to all IPv4 interfaces.
    # Allow TIME_WAIT sockets from a previous trial, but reject a live listener
    # before its health response could be mistaken for the new container's.
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
        probe.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            probe.bind(("0.0.0.0", port))
        except OSError as error:
            if error.errno != errno.EADDRINUSE:
                raise
            raise RuntimeError(
                f"Server port {port} is already in use; stop the existing "
                "server or choose a different --port."
            ) from error


def start_container(benchmark, name, args):
    ensure_server_port_available(args.port)
    os.makedirs(args.hf_cache, exist_ok=True)
    cmd = build_container_cmd(benchmark, name, args)

    run_cmd([PODMAN, "rm", "-f", name], check=False)
    benchmark.state.started_containers.add(name)
    started_ns = time.monotonic_ns()
    run_cmd(cmd, env=podman_env(benchmark, args))
    print(f"  waiting for {name} health on {args.base_url}", flush=True)
    wait_health(args.base_url, args.health_path, args.wait_seconds, name,
                benchmark.adapter.display_name)
    return {
        "started_ns": started_ns,
        "to_health_us": (time.monotonic_ns() - started_ns) // 1000,
    }


def checkpoint_container(benchmark, name, archive, cfg, args):
    set_runc_conf_for_cfg(benchmark, args.runc_conf, cfg,
                          args.compress_acceleration,
                          args.decompress_threads)
    cmd = [PODMAN, "container", "checkpoint", "--file-locks", "--tcp-established"]
    if getattr(args, "checkpoint_storage", "archive") == "archive":
        cmd += ["--export", archive, "--compress", args.archive_compression,
                "--ignore-volumes"]
    if args.print_stats:
        cmd.append("--print-stats")
    if (args.keep_checkpoint_files or benchmark.state.trial_artifacts
            or getattr(args, "checkpoint_storage", "archive") == "local"):
        cmd.append("--keep")
    cmd.append(name)

    return podman_operation(benchmark, name, cmd, "checkpoint", args)


def _tar_command(cmd, binary=False):
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=not binary)
    except OSError as exc:
        raise RuntimeError(f"unable to inspect checkpoint archive: {exc}") from exc
    if result.returncode:
        stderr = result.stderr
        if binary:
            stderr = stderr.decode(errors="replace")
        raise RuntimeError(
            "unable to inspect checkpoint archive: " + stderr.strip()[-2000:]
        )
    return result.stdout


def inventory_bytes_from_archive(archive):
    listing = _tar_command(["tar", "--list", "--file", archive])
    inventories = [
        member for member in listing.splitlines()
        if posixpath.basename(member.rstrip("/")) == "inventory.img"
    ]
    if len(inventories) != 1:
        raise RuntimeError(
            "checkpoint archive must contain exactly one inventory.img; "
            f"found {len(inventories)}"
        )
    return _tar_command([
        "tar", "--extract", "--to-stdout", "--file", archive,
        "--", inventories[0],
    ], binary=True)


def inventory_entry_from_archive(archive):
    if os.path.join(REPO_ROOT, "lib") not in sys.path:
        sys.path.insert(0, os.path.join(REPO_ROOT, "lib"))
    try:
        from pycriu import images as pimg
        source = Path(archive)
        payload = ((source / "inventory.img").read_bytes() if source.is_dir()
                   else inventory_bytes_from_archive(archive))
        inventory = pimg.loads(payload)
    except Exception as exc:
        raise RuntimeError(
            "unable to decode checkpoint inventory; build the CRIU Python "
            f"bindings with 'make -C {REPO_ROOT} lib': {exc}"
        ) from exc
    if inventory.get("magic") != "INVENTORY":
        raise RuntimeError("checkpoint inventory has the wrong image magic")
    entries = inventory.get("entries", [])
    if len(entries) != 1:
        raise RuntimeError(
            f"checkpoint inventory must contain one entry; found {len(entries)}"
        )
    return entries[0]


def verify_archive_compression(archive, cfg):
    entry = inventory_entry_from_archive(archive)
    expected = {"uncompressed": 0, "lz4-block": 1}[cfg["mode"]]
    try:
        actual = int(entry.get("compress", 0))
    except (TypeError, ValueError) as exc:
        raise RuntimeError("checkpoint inventory has an invalid compression mode") from exc
    if actual != expected:
        raise RuntimeError(
            "checkpoint compression mode does not match the benchmark "
            f"configuration: expected {expected}, found {actual}"
        )
    if expected == 1:
        try:
            block_size = int(entry.get("compress_block_size", 0))
        except (TypeError, ValueError) as exc:
            raise RuntimeError(
                "checkpoint inventory has an invalid compression block size"
            ) from exc
        if block_size != cfg["block_size"]:
            raise RuntimeError(
                "checkpoint compression block does not match the benchmark "
                f"configuration: expected {cfg['block_size']}, found {block_size}"
            )
    return actual


def restore_container(benchmark, name, archive, args):
    cmd = [PODMAN, "container", "restore", "--file-locks", "--tcp-established"]
    if getattr(args, "checkpoint_storage", "archive") == "archive":
        cmd += ["--import", archive, "--ignore-volumes"]
    else:
        cmd.append(name)
    if args.print_stats:
        cmd.append("--print-stats")
    if (args.keep_checkpoint_files or benchmark.state.trial_artifacts
            or getattr(args, "checkpoint_storage", "archive") == "local"):
        cmd.append("--keep")

    started_ns = time.monotonic_ns()
    benchmark.state.started_containers.add(name)
    restore_us, stats = podman_operation(benchmark, name, cmd, "restore", args)
    # A memory-released serving process may deliberately report unhealthy
    # until its accelerator allocations and worker loops are resumed. Resume
    # immediately after the runtime restore, before polling application health.
    after_restore = getattr(benchmark.adapter, "after_restore", None)
    resume_us = 0
    if after_restore is not None:
        with trial_phase(benchmark, "resume application"):
            resume_started_ns = time.monotonic_ns()
            after_restore(args)
            resume_us = (time.monotonic_ns() - resume_started_ns) // 1000
    print(f"  waiting for restored {name} health on {args.base_url}", flush=True)
    wait_health(args.base_url, args.health_path, args.wait_seconds, name,
                benchmark.adapter.display_name)
    return {
        "started_ns": started_ns,
        "command_us": restore_us,
        "application_resume_us": resume_us,
        "to_health_us": (time.monotonic_ns() - started_ns) // 1000,
        "stats": stats,
    }


def run_trial(benchmark, cfg, workdir, args, trial_id, keep_running=False):
    name = f"{args.container_name}-{os.getpid()}-{trial_id}"
    archive = os.path.join(workdir, f"{name}.tar")
    if args.archive_compression == "gzip":
        archive += ".gz"
    elif args.archive_compression == "zstd":
        archive += ".zst"
    artifacts = prepare_trial(benchmark, workdir, args, trial_id)
    with trial_phase(benchmark, "start server"):
        cold_start = benchmark.start_container(name, args)
    request_model = args.served_model_name or args.model
    cold_timing = benchmark.chat_stream_once(
        args.base_url, request_model, args.prompt, args.max_tokens,
        args.temperature, args.seed, args.request_timeout,
        cold_start["started_ns"], args.chat_extra_json,
    )
    for _ in range(args.warmup_requests):
        benchmark.chat_once(args.base_url, request_model, args.prompt,
                            args.max_tokens, args.temperature, args.seed,
                            args.request_timeout, args.chat_extra_json)
    pre_timing = benchmark.chat_stream_once(
        args.base_url, request_model, args.prompt, args.max_tokens,
        args.temperature, args.seed, args.request_timeout,
        cold_start["started_ns"], args.chat_extra_json,
    )
    pre_us = pre_timing["request_us"]
    pre_content = pre_timing["content"]
    write_json(artifacts / "validation.json", {"cold": cold_timing, "before": pre_timing})
    storage_path = checkpoint_storage_path(name, workdir, args)
    observe_host(benchmark, "before-release", storage_path, args)
    before_checkpoint = getattr(benchmark.adapter, "before_checkpoint", None)
    preparation_us = 0
    if before_checkpoint is not None:
        with trial_phase(benchmark, "pause and release application memory"):
            prepare_started_ns = time.monotonic_ns()
            before_checkpoint(args)
            preparation_us = (time.monotonic_ns() - prepare_started_ns) // 1000
    observe_host(benchmark, "after-release", storage_path, args)
    with trial_phase(benchmark, "checkpoint"):
        checkpoint_us, checkpoint_stats = benchmark.checkpoint_container(name, archive, cfg, args)
    checkpoint = inspect_checkpoint(benchmark, name, archive, cfg, args)
    if checkpoint["checkpoint_storage"] == "archive":
        remove_container(name)
        benchmark.state.started_containers.discard(name)
    observe_host(benchmark, "before-restore", storage_path, args)
    with trial_phase(benchmark, "condition restore cache"):
        cache_policy = condition_restore_cache(benchmark, name, archive, args)
    with trial_phase(benchmark, "restore and validate inference"):
        restore_timing = benchmark.restore_container(name, archive, args)
        post_timing = benchmark.chat_stream_once(
            args.base_url, request_model, args.prompt, args.max_tokens,
            args.temperature, args.seed, args.request_timeout,
            restore_timing["started_ns"], args.chat_extra_json,
        )
    write_json(artifacts / "validation.json", {
        "cold": cold_timing, "before": pre_timing, "after": post_timing,
    })
    save_container_artifacts(benchmark, name, "restore")
    observe_host(benchmark, "after-restore", storage_path, args)
    post_us = post_timing["request_us"]
    post_content = post_timing["content"]
    pre_digest = hashlib.sha256(pre_content.encode()).hexdigest()
    post_digest = hashlib.sha256(post_content.encode()).hexdigest()
    valid = pre_digest == post_digest
    if not valid:
        with open(os.path.join(workdir, "validation.json"), "w") as output:
            json.dump({"before": pre_content, "after": post_content}, output,
                      indent=2)
        raise RuntimeError(
            "deterministic validation response changed after restore: "
            f"before_sha256={pre_digest}, after_sha256={post_digest}"
        )
    measurements = measurement_results(benchmark, checkpoint_stats, restore_timing["stats"], args, cfg)
    retain_checkpoint(benchmark, name, archive, args)
    if keep_running:
        # Exempt only the explicitly retained final container from atexit
        # cleanup. Earlier trials must release the shared host-network port.
        benchmark.state.started_containers.discard(name)
    else:
        remove_container(name)
        benchmark.state.started_containers.discard(name)

    return {
        **checkpoint,
        **measurements,
        "application_prepare_us": preparation_us,
        "application_resume_us": restore_timing.get("application_resume_us", 0),
        "checkpoint_wall_us": checkpoint_us,
        "restore_wall_us": restore_timing["command_us"],
        "server_start_to_health_us": cold_start["to_health_us"],
        "cold_start_to_first_token_us": cold_timing[
            "operation_to_first_token_us"
        ],
        "cold_start_to_response_complete_us": cold_timing[
            "operation_to_response_complete_us"
        ],
        "cold_start_request_ttft_us": cold_timing[
            "request_to_first_token_us"
        ],
        "restore_to_health_us": restore_timing["to_health_us"],
        "restore_to_first_token_us": post_timing[
            "operation_to_first_token_us"
        ],
        "restore_to_response_complete_us": post_timing[
            "operation_to_response_complete_us"
        ],
        "restore_request_ttft_us": post_timing[
            "request_to_first_token_us"
        ],
        "pre_request_us": pre_us,
        "post_request_us": post_us,
        "checkpoint_stats": checkpoint_stats,
        "restore_stats": restore_timing["stats"],
        "validation_response_sha256": post_digest,
        "cache_policy": cache_policy,
        "gpu_state": "released" if getattr(args, "memory_saver", False) else "live",
        "checkpoint_boundary": "between completed requests",
        "artifacts": str(artifacts),
        "valid": valid,
        "framework": benchmark.adapter.key,
        "container_name": name if keep_running else None,
    }


def json_config(args):
    result = vars(args).copy()
    result["env"] = [
        f"{item.split('=', 1)[0]}=<redacted>" if "=" in item else item
        for item in args.env
    ]
    result["run_arg"] = redact_run_args(getattr(args, "run_arg", []))
    return result


def parse_podman_stats(raw, operation, required=False):
    """Extract one container's runtime and CRIU stats; durations are microseconds."""
    if raw is None or raw == "":
        if required:
            raise RuntimeError(f"Missing Podman {operation} statistics")
        return None, None, {}
    try:
        data = json.loads(raw) if isinstance(raw, str) else raw
        if not isinstance(data, dict):
            raise ValueError("expected a JSON object")
        containers = data.get("container_statistics")
        if not isinstance(containers, list) or len(containers) != 1:
            raise ValueError("expected exactly one container_statistics entry")
        container = containers[0]
        if not isinstance(container, dict):
            raise ValueError("invalid container_statistics entry")
        duration = container.get(f"runtime_{operation}_duration")
        if type(duration) is not int or duration < 0:
            raise ValueError("runtime duration must be a nonnegative integer")
        criu = container.get("criu_statistics")
        if not isinstance(criu, dict):
            raise ValueError("missing criu_statistics object")
        if any(key.endswith("_time") and (type(value) is not int or value < 0)
               for key, value in criu.items()):
            raise ValueError("CRIU durations must be nonnegative integers")
    except (ValueError, TypeError) as error:
        raise RuntimeError(f"Invalid Podman {operation} statistics: {error}") from error
    return data, duration, criu


def parse_cuda_timings(log, operation, backend, required=False):
    """Keep every dispatched hook, including unsupported tasks and errors."""
    import re

    backend_names = {"Driver API": "driver-api", "cuda-checkpoint CLI": "cuda-checkpoint"}
    selected = [backend_names.get(name, name) for name in re.findall(
        r"cuda_plugin: selected ([^\n]+?) backend for stage \d+", log)]
    if backend and (not selected or any(value != backend for value in selected)):
        raise RuntimeError(f"Missing or mismatched {operation} CUDA backend evidence: "
                           f"expected {backend}, found {selected}")
    pattern = (r"cuda_plugin: timing backend=(\S+) phase=(\S+) pid=(-?\d+) "
               r"ret=(-?\d+) elapsed_us=(\d+)(?:\s|$)")
    records = []
    for match in re.finditer(pattern, log):
        name, phase, pid, ret, elapsed = match.groups()
        if backend and name != backend:
            raise RuntimeError(f"Unexpected {operation} CUDA timing backend: {name}")
        records.append({"operation": operation, "backend": name, "phase": phase,
                        "pid": int(pid), "ret": int(ret), "elapsed_us": int(elapsed)})
    if len(records) != log.count("cuda_plugin: timing "):
        raise RuntimeError(f"Malformed {operation} CUDA timing record")
    if required:
        expected = {"init", "checkpoint_devices" if operation == "checkpoint"
                    else "resume_devices_late"}
        missing = expected - {record["phase"] for record in records}
        if missing:
            raise RuntimeError(f"Missing {operation} CUDA timings: {', '.join(sorted(missing))}")
    return records


def measurement_results(benchmark, checkpoint_stats, restore_stats, args, cfg=None):
    """Normalize timings and retain evidence after the timed operations finish."""
    result = {"cuda_timings": []}
    artifacts = benchmark.state.trial_artifacts
    backend = (cfg or {}).get("cuda_backend")
    timings_required = bool(backend and getattr(args, "cuda_timings", False))
    for operation, raw, stats_key, log_name in (
        ("checkpoint", checkpoint_stats, "criu_dump_stats", "dump.log"),
        ("restore", restore_stats, "criu_restore_stats", "restore.log"),
    ):
        data, duration, criu = (parse_podman_stats(raw, operation, required=True)
                               if getattr(args, "print_stats", False)
                               else (None, None, {}))
        result[f"{operation}_runtime_us"] = duration
        result[stats_key] = criu
        if artifacts is not None and data is not None:
            destination = Path(artifacts) / operation
            destination.mkdir(exist_ok=True)
            write_json(destination / "podman-stats.json", data)
        if backend:
            if artifacts is None:
                raise RuntimeError("CUDA backend comparison requires preserved CRIU logs")
            path = Path(artifacts) / operation / log_name
            try:
                log = path.read_text(errors="replace")
            except OSError as error:
                raise RuntimeError(f"Unable to read CUDA backend evidence {path}: {error}") from error
            result["cuda_timings"].extend(parse_cuda_timings(
                log, operation, backend, required=timings_required))
    return result


def measurement_summary(values, formatter=format_duration):
    if not values:
        return "unavailable (n=0)"
    return (f"{formatter(median(values))} "
            f"[{formatter(min(values))}, {formatter(max(values))}] (n={len(values)})")


def paired_runtime_differences(first, second, key):
    """Match two configurations by global trial round, not result-list position."""
    groups = []
    for trials in (first, second):
        by_round = {}
        for trial in trials:
            number, value = trial.get("trial"), trial.get(key)
            if (type(number) is not int or number < 1 or type(value) is not int
                    or value < 0 or not trial.get("valid")):
                continue
            round_index = (number - 1) // 2
            if round_index in by_round:
                raise RuntimeError(f"Multiple {key} samples in paired trial round {round_index}")
            by_round[round_index] = value
        groups.append(by_round)
    return [groups[1][index] - groups[0][index]
            for index in sorted(groups[0].keys() & groups[1].keys())]


def signed_duration(value):
    sign = "+" if value > 0 else "-" if value < 0 else ""
    return sign + format_duration(abs(value))


def report(benchmark, results_by_cfg, order):
    print(f"\n  PODMAN {benchmark.adapter.heading}")
    ok = all(r["valid"] for trials in results_by_cfg.values() for r in trials)
    print(f"  Inference validation: {'PASS' if ok else 'FAIL'}")
    print("  Values: median [min, max], measured samples only.")
    print("  OCI, CRIU and CUDA timings are nested; do not add them to command wall time.")
    baseline = "Uncompressed" if "Uncompressed" in results_by_cfg else order[0]
    baseline_sizes = [r.get("checkpoint_size", r.get("archive_size"))
                      for r in results_by_cfg[baseline]]
    baseline_size = median([size for size in baseline_sizes if size is not None])
    print(f"  Storage baseline: {baseline}")
    for label in order:
        trials = results_by_cfg[label]
        print(f"\n  {label}: n={len(trials)}")
        if len(trials) < 4:
            print("    INCONCLUSIVE: fewer than four measured trials; no backend ranking.")
        sizes = [r.get("checkpoint_size", r.get("archive_size")) for r in trials]
        sizes = [size for size in sizes if size is not None]
        print("    Checkpoint size: " + measurement_summary(
            sizes, lambda size: f"{size / (1024 ** 3):.2f} GiB"))
        if sizes and baseline_size:
            ratio = median(sizes) / baseline_size
            print(f"    Size relative to baseline: {ratio:.3f}x ({1 - ratio:.0%} saved)")
        metrics = (
            ("Application checkpoint preparation", "application_prepare_us"),
            ("Checkpoint command wall", "checkpoint_wall_us"),
            ("Checkpoint OCI runtime", "checkpoint_runtime_us"),
            ("Restore command wall", "restore_wall_us"),
            ("Restore OCI runtime", "restore_runtime_us"),
            ("Application resume", "application_resume_us"),
            ("Restore to health", "restore_to_health_us"),
            ("Restore to first token", "restore_to_first_token_us"),
            ("Restore to first audio packet", "restore_to_first_audio_packet_us"),
            ("Restore to response complete", "restore_to_response_complete_us"),
            ("Restore to session complete", "restore_to_session_complete_us"),
            ("Request after restore", "post_request_us"),
        )
        for title, key in metrics:
            values = [r[key] for r in trials if r.get(key) is not None]
            if values or key in ("checkpoint_runtime_us", "restore_runtime_us"):
                print(f"    {title}: {measurement_summary(values)}")
        for title, stats_key, key in (
            ("CRIU freezing", "criu_dump_stats", "freezing_time"),
            ("CRIU frozen", "criu_dump_stats", "frozen_time"),
            ("CRIU restore", "criu_restore_stats", "restore_time"),
        ):
            values = [r[stats_key][key] for r in trials if key in r.get(stats_key, {})]
            if values:
                print(f"    {title}: {measurement_summary(values)}")
        phases = sorted({(record["operation"], record["phase"])
                         for r in trials for record in r.get("cuda_timings", [])})
        for operation, phase in phases:
            values, handled, unsupported, errors = [], 0, 0, 0
            for trial in trials:
                records = [record for record in trial.get("cuda_timings", [])
                           if (record["operation"], record["phase"]) == (operation, phase)]
                if records:
                    values.append(sum(record["elapsed_us"] for record in records))
                handled += sum(record["ret"] == 0 for record in records)
                unsupported += sum(record["ret"] == -errno.ENOTSUP for record in records)
                errors += sum(record["ret"] not in (0, -errno.ENOTSUP) for record in records)
            print(f"    CUDA {operation}/{phase}: {measurement_summary(values)}; "
                  f"calls ok={handled}, unsupported={unsupported}, error={errors}")
    if len(order) == 2:
        first, second = order
        print(f"\n  PAIRED OCI DIFFERENCES: {second} minus {first}")
        print("  Positive means the first configuration was faster; negative means the second.")
        for operation in ("checkpoint", "restore"):
            differences = paired_runtime_differences(
                results_by_cfg[first], results_by_cfg[second], f"{operation}_runtime_us")
            print(f"    {operation.capitalize()}: "
                  f"{measurement_summary(differences, signed_duration)}")
            reasons = []
            if len(differences) < 4:
                reasons.append("fewer than four complete pairs")
            if differences and min(differences) <= 0 <= max(differences):
                reasons.append("paired difference range includes zero")
            if reasons:
                print("      INCONCLUSIVE: " + "; ".join(reasons) + ".")
        print("  Pairs use trial rounds; these are observed differences, not a significance test.")


def run_main(benchmark, argv=None, description=None):
    adapter = benchmark.adapter
    runtime = benchmark.state
    ap = argparse.ArgumentParser(description=description,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--accelerator", choices=["gpu", "cpu"], default="gpu",
                    help="Inference accelerator (default: gpu)")
    adapter.add_image_arguments(ap)
    ap.add_argument("--model", default="Qwen/Qwen3-0.6B")
    ap.add_argument("--served-model-name",
                    help="Model name to use in OpenAI API requests; defaults "
                         "to --model")
    adapter.add_model_arguments(ap)
    ap.add_argument("--port", type=int, default=30000)
    ap.add_argument("--base-url",
                    help="Server URL (default: http://127.0.0.1:PORT)")
    ap.add_argument("--health-path", default="/health")
    ap.add_argument("--container-name", default=adapter.default_container_name)
    ap.add_argument("-n", "--iterations", type=int, default=3)
    ap.add_argument("--modes", nargs="+",
                    default=["uncompressed", "lz4-block"],
                    choices=["uncompressed", "lz4-block"],
                    help="CRIU memory page compression modes to compare")
    ap.add_argument("--block-sizes", nargs="+", type=int,
                    default=DEFAULT_BLOCK_SIZES,
                    help="Block sizes in bytes when --modes contains "
                         "lz4-block (default: page size and supported values "
                         "among 64K, 256K, and 1M)")
    ap.add_argument("--compress-acceleration", type=int, default=1,
                    help="CRIU LZ4 acceleration level")
    ap.add_argument("--decompress-threads", type=int, default=None,
                    help="CRIU LZ4/zero-fill worker concurrency "
                         "(default: unset = CRIU default; 0 = auto; "
                         "1 = serial per request; N > 1 = aggregate worker limit); "
                         "written to runc.conf")
    ap.add_argument("--runc-conf", default="/etc/criu/runc.conf",
                    help="CRIU config file read by runc during Podman checkpoint")
    ap.add_argument("--archive-compression", default="none",
                    choices=["none", "gzip", "zstd"],
                    help="Podman checkpoint archive compression")
    ap.add_argument("--checkpoint-storage", choices=["local", "archive"], default="archive",
                    help="Restore local container images or export/import an archive")
    ap.add_argument("--cache-policy", choices=["uncontrolled", "cold"], default="uncontrolled",
                    help="Cold synchronizes and drops HOST caches before restore; use an idle host")
    ap.add_argument("--offline", action="store_true",
                    help="Require prepopulated Hugging Face files; disable runtime Hub downloads")
    ap.add_argument("--cuda-timings", action=argparse.BooleanOptionalAction, default=True,
                    help="Record CUDA plugin phase timings for backend comparisons")
    ap.add_argument("--criu-libdir", default=os.environ.get("CRIU_LIBS_DIR"),
                    help="Directory containing CRIU plugin .so files")
    ap.add_argument("--hf-cache", default=os.path.expanduser("~/.cache/huggingface"))
    ap.add_argument("--gpu-device", default="nvidia.com/gpu=all",
                    help="GPU device selector passed to podman --device")
    ap.add_argument("--security-opt", default="label=disable",
                    help="Security option passed to podman --security-opt")
    ap.add_argument("--cuda-visible-devices", default="0")
    ap.add_argument("--shm-size", default="32g")
    adapter.add_resource_arguments(ap)
    ap.add_argument("--prompt", default="Say hello in one short sentence.")
    ap.add_argument("--prompt-file",
                    help="Read the validation/warmup prompt from a text file")
    ap.add_argument("--max-tokens", type=int, default=32)
    ap.add_argument("--temperature", type=float, default=0,
                    help="Chat completion temperature for validation requests")
    ap.add_argument("--seed", type=int, default=42,
                    help="Chat completion seed used before and after restore")
    ap.add_argument("--chat-extra-json", type=json_object,
                    help="JSON object merged into every chat completion request")
    adapter.add_request_arguments(ap)
    ap.add_argument("--warmup-requests", type=int, default=0,
                    help="Extra successful chat requests to issue before the "
                         "measured pre-checkpoint request")
    ap.add_argument("--wait-seconds", type=int, default=900)
    ap.add_argument("--request-timeout", type=int, default=180)
    ap.add_argument("--command-timeout", type=int, default=3600,
                    help="Maximum seconds for each Podman checkpoint or restore command")
    ap.add_argument("--env", action="append", default=[],
                    help="Extra container environment entry, e.g. KEY=VALUE")
    ap.add_argument("--volume", action="append", default=[],
                    help="Extra container volume, e.g. /host:/container")
    ap.add_argument("--run-arg", action="append", default=[],
                    help="Extra raw argument for podman run before the image")
    ap.add_argument("--ulimit", action="append", default=[],
                    help="Extra Podman ulimit, e.g. nofile=65535:524288")
    adapter.add_server_arguments(ap)
    ap.add_argument("--print-stats", action="store_true",
                    help="Ask Podman to print checkpoint/restore stats")
    ap.add_argument("--keep-checkpoint-files", action="store_true",
                    help="Retain large checkpoint images as well as per-trial diagnostics")
    ap.add_argument("--artifacts-dir", help="New persistent directory (default: JSON stem.artifacts)")
    ap.add_argument("--keep-running", action="store_true",
                    help="Leave only the final measured restored container "
                         "running")
    ap.add_argument("--json", metavar="FILE", help="Write raw results to JSON")
    args = ap.parse_args(argv)
    args.base_url = server_base_url(args.port, args.base_url)

    if args.iterations <= 0:
        ap.error("--iterations must be greater than zero")
    if args.command_timeout <= 0 or args.request_timeout <= 0 or args.wait_seconds <= 0:
        ap.error("command, request and readiness timeouts must be positive")
    if args.warmup_requests < 0:
        ap.error("--warmup-requests must be nonnegative")
    if args.checkpoint_storage == "local" and args.archive_compression != "none":
        ap.error("--archive-compression requires --checkpoint-storage archive")
    if not 1 <= args.compress_acceleration <= MAX_COMPRESSION_ACCELERATION:
        ap.error("--compress-acceleration must be between 1 and "
                 f"{MAX_COMPRESSION_ACCELERATION}")
    if args.decompress_threads is not None and \
            not 0 <= args.decompress_threads <= MAX_DECOMPRESSION_THREADS:
        ap.error("--decompress-threads must be between 0 and "
                 f"{MAX_DECOMPRESSION_THREADS}")
    if any(size <= 0 or size > MAX_BLOCK_SIZE or size % PAGE_SIZE
           for size in args.block_sizes):
        ap.error(f"--block-sizes must be positive multiples of {PAGE_SIZE} "
                 f"not exceeding {MAX_BLOCK_SIZE}")
    if len(args.modes) != len(set(args.modes)):
        ap.error("--modes must not contain duplicate values")
    if len(args.block_sizes) != len(set(args.block_sizes)):
        ap.error("--block-sizes must not contain duplicate values")
    if any(item.split("=", 1)[0] in HF_TOKEN_ENV_VARS for item in args.env):
        ap.error("set Hugging Face tokens in the host environment instead of "
                 "passing their values through --env")
    if any(run_arg_sets_environment(item) for item in args.run_arg):
        ap.error("pass environment entries through --env, not --run-arg")
    adapter.normalize_args(ap, args)
    args.cuda_timings = args.cuda_timings and bool(getattr(args, "cuda_backends", None))
    if os.getuid() != 0:
        sys.exit("Error: run as root so Podman/CRIU can checkpoint the container")
    runtime.cleanup_containers = True

    import atexit
    for handled in SIGNALS:
        signal.signal(
            handled,
            lambda signum, frame: signal_handler(benchmark, signum, frame),
        )
    atexit.register(cleanup, benchmark)

    info = collect_system_info()
    print()
    if args.json and Path(args.json).exists():
        raise RuntimeError(f"Results already exist: {args.json}")
    if args.artifacts_dir or args.json:
        args.artifacts_dir = str(Path(args.artifacts_dir or Path(args.json).with_suffix(".artifacts")).absolute())
        Path(args.artifacts_dir).mkdir()
    else:
        args.artifacts_dir = tempfile.mkdtemp(prefix=adapter.temp_prefix + "results-")
    adapter.prepare_args(args)
    info["benchmark"] = {
        "git_revision": run_cmd(["git", "-C", REPO_ROOT, "rev-parse", "HEAD"]).stdout.strip(),
        "dirty": bool(run_cmd(["git", "-C", REPO_ROOT, "status", "--porcelain"]).stdout.strip()),
        "source_sha256": {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in Path(__file__).parent.glob("*.py")
        },
    }
    if getattr(args, "cuda_backends", None):
        info["cuda_benchmark"] = cuda_benchmark_identity(args)
    if args.prompt_file:
        prompt = read_file(args.prompt_file)
        if prompt is None:
            sys.exit(f"Error: prompt file not found: {args.prompt_file}")
        args.prompt = prompt.rstrip("\n")

    print(f"Podman {adapter.display_name} Checkpoint/Restore Benchmark")
    print(f"  Kernel : {info.get('kernel', '?')}")
    print(f"  CPU    : {info.get('cpu', '?')}")
    print(f"  Memory : {info.get('memory_mb', '?')} MB")
    print(f"  GPU    : {', '.join(info.get('gpus', ['?']))}")
    print(f"  Accelerator: {args.accelerator}")
    print(f"  Podman : {info.get('podman', '?')}")
    print(f"  CRIU   : {info.get('criu', '?')}")
    print(f"  Plugin : {args.criu_libdir or 'default CRIU plugin path'}")
    print(f"  Runc conf: {args.runc_conf}")
    print(f"  Storage: {args.checkpoint_storage}; archive compression={args.archive_compression}")
    print(f"  Restore cache: {args.cache_policy}; offline={args.offline}")
    print(f"  Artifacts: {args.artifacts_dir}")

    cfgs = []
    for mode in args.modes:
        if mode == "lz4-block":
            for bs in args.block_sizes:
                cfgs.append({"mode": "lz4-block", "block_size": bs})
        else:
            cfgs.append({"mode": mode, "block_size": 0})
    if getattr(args, "cuda_backends", None):
        cfgs = [dict(cfg, cuda_backend=backend, cuda_timings=args.cuda_timings,
                     criu_libdir=os.path.abspath(args.criu_libdir))
                for backend in args.cuda_backends for cfg in cfgs]
    labels = [cfg_label(cfg) for cfg in cfgs]

    print(f"  Config : {args.iterations}+1 iterations, "
          f"modes={','.join(labels)}")
    print("  Restore: decompress-threads="
          f"{decompress_threads_label(args.decompress_threads)}")
    print(f"  Server : {args.base_url}, model={args.model}, "
          f"{adapter.server_summary(args)}")
    request_summary = getattr(adapter, "request_summary", None)
    if request_summary is not None:
        print(f"  Request: {request_summary(args)}")
    else:
        print(f"  Request: max_tokens={args.max_tokens}, "
              f"temperature={args.temperature:g}, "
              f"warmup_requests={args.warmup_requests}")
    if args.prompt_file:
        print(f"  Prompt : {args.prompt_file}")
    if args.ulimit:
        print(f"  Ulimit : {','.join(args.ulimit)}")

    results = {label: [] for label in labels}
    warmups = {label: [] for label in labels}
    failures = []

    def save_results(status):
        if not args.json:
            return
        destination = os.path.abspath(args.json)
        with open(destination + ".tmp", "w") as output:
            json.dump({"schema_version": 2, "system": info, "framework": adapter.key,
                       "config": json_config(args), "results": results,
                       "warmups": warmups, "failures": failures,
                       "status": status}, output, indent=2)
        os.replace(destination + ".tmp", destination)

    save_results("running")
    total = args.iterations + 1
    trial = 0
    for i in range(total):
        warmup = (i == 0)
        configurations = list(zip(cfgs, labels))
        offset = i % len(configurations)
        configurations = configurations[offset:] + configurations[:offset]
        for config_index, (cfg, label) in enumerate(configurations):
            trial += 1
            print(f"\n  Trial {trial}/{total * len(cfgs)}: {label} "
                  f"({'warmup, excluded' if warmup else f'measured {i}/{args.iterations}'})", flush=True)
            workdir = tempfile.mkdtemp(prefix=adapter.temp_prefix)
            runtime.tempdirs.add(workdir)
            runtime.trial_artifacts = None
            try:
                retain = (args.keep_running and not warmup and
                          i == total - 1 and
                          config_index == len(configurations) - 1)
                result = benchmark.run_trial(cfg, workdir, args, trial, retain)
            except BaseException as e:
                failure_artifacts = str(runtime.trial_artifacts or workdir)
                failures.append({"trial": trial, "warmup": warmup,
                                "configuration": cfg, "error": str(e) or type(e).__name__,
                                "artifacts": failure_artifacts, "checkpoint_workdir": workdir})
                runtime.tempdirs.discard(workdir)
                print(f"\n  ERROR: {label}: {e}", file=sys.stderr)
                print(f"  Artifacts preserved in {failure_artifacts}", file=sys.stderr)
                name = f"{args.container_name}-{os.getpid()}-{trial}"
                for phase in ("checkpoint", "restore"):
                    try:
                        save_container_artifacts(benchmark, name, phase, required=False)
                    except (OSError, RuntimeError, KeyError, TypeError) as diagnostic_error:
                        print(f"Unable to collect {phase} diagnostics: {diagnostic_error}", file=sys.stderr)
                try:
                    diagnostics = container_diagnostics(name)
                    print(diagnostics, file=sys.stderr)
                    if runtime.trial_artifacts:
                        (runtime.trial_artifacts / "failure.log").write_text(diagnostics)
                except Exception as diagnostic_error:
                    print(f"Unable to collect container diagnostics: {diagnostic_error}", file=sys.stderr)
                try:
                    save_results("interrupted" if isinstance(e, (SystemExit, KeyboardInterrupt)) else "failed")
                except OSError as save_error:
                    print(f"Unable to save failed trial: {save_error}",
                          file=sys.stderr)
                raise
            else:
                result.update(trial=trial, configuration=cfg)
                if runtime.trial_artifacts:
                    write_json(runtime.trial_artifacts / "result.json", dict(result, warmup=warmup))
                samples = warmups if warmup else results
                samples[label].append(result)
                shutil.rmtree(workdir)
                runtime.tempdirs.discard(workdir)
            save_results("running")
        print(f"  completed {'warmup' if warmup else f'{i}/{args.iterations}'}")

    benchmark.report(results, labels)

    # A successful benchmark must not report success until the host-wide
    # CRIU configuration is restored. atexit remains a fallback for errors
    # and signals, where cleanup diagnostics cannot change an existing status.
    benchmark.restore_runc_conf()
    save_results("complete")
    if args.json:
        print(f"Results written to {args.json}")
    print()
