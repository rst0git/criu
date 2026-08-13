#!/usr/bin/env python3
"""Dynamo-style serving lifecycle helpers for Podman CRIU benchmarks."""

import importlib.util
import os
import subprocess
import sys
import time

import podman_common as common


# Keep this list aligned with Dynamo's snapshot capture environment.  These
# settings are deliberately local to the opt-in Dynamo benchmark drivers.
SNAPSHOT_CAPTURE_ENV = {
    "NCCL_CUMEM_ENABLE": "0",
    "NCCL_NVLS_ENABLE": "0",
    "NCCL_IB_DISABLE": "1",
    "NCCL_RAS_ENABLE": "0",
    "TORCH_NCCL_ENABLE_MONITORING": "0",
    "HF_HUB_OFFLINE": "1",
}

SNAPSHOT_CAPTURE_DEFAULT_ENV = {
    "TORCH_NCCL_DUMP_ON_TIMEOUT": "0",
}

LIFECYCLE_METRICS = (
    "pause_generation_us",
    "sleep_or_release_us",
    "quiesce_us",
    "quiesce_to_checkpoint_complete_us",
    "wake_up_us",
    "resume_generation_us",
    "wake_or_resume_us",
    "gpu_memory_before_release_bytes",
    "gpu_memory_after_release_bytes",
    "gpu_memory_after_runtime_restore_bytes",
    "gpu_memory_after_wake_bytes",
    "recovery_total_us",
)


def load_legacy_driver(filename):
    """Load a sibling hyphenated benchmark driver without copying its CLI."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), filename)
    module_name = "_compression_benchmark_" + filename.replace("-", "_").replace(
        ".py", ""
    )
    spec = importlib.util.spec_from_file_location(module_name, path)
    if spec is None or spec.loader is None:
        raise RuntimeError(f"unable to load benchmark driver: {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[module_name] = module
    spec.loader.exec_module(module)
    return module


def configure_snapshot_capture_env(args, extra=None):
    """Apply Dynamo's forced and set-if-unset capture environment."""
    required = dict(SNAPSHOT_CAPTURE_ENV)
    required.update(extra or {})
    retained = []
    for item in args.env:
        name = item.partition("=")[0]
        if name in required:
            continue
        retained.append(item)
    args.env[:] = retained
    for name, value in required.items():
        args.env.append(f"{name}={value}")
    configured_names = {item.partition("=")[0] for item in args.env}
    for name, value in SNAPSHOT_CAPTURE_DEFAULT_ENV.items():
        if name not in configured_names:
            args.env.append(f"{name}={value}")


def lifecycle_metrics(args):
    metrics = getattr(args, "_dynamo_lifecycle_metrics", None)
    if metrics is None:
        raise RuntimeError("Dynamo lifecycle metrics were not initialized")
    return metrics


def gpu_memory_used_bytes(args):
    """Return memory.used for the selected physical GPU in bytes."""
    if getattr(args, "accelerator", None) != "gpu":
        return None
    gpu_id = str(args.cuda_visible_devices).split(",", 1)[0]
    command = [
        "nvidia-smi",
        f"--id={gpu_id}",
        "--query-gpu=memory.used",
        "--format=csv,noheader,nounits",
    ]
    try:
        result = subprocess.run(command, capture_output=True, text=True)
    except OSError as error:
        raise RuntimeError(f"unable to sample GPU memory: {error}") from error
    if result.returncode:
        detail = (result.stderr or result.stdout).strip()
        raise RuntimeError(f"unable to sample GPU memory: {detail[-1000:]}")
    try:
        mebibytes = int(result.stdout.splitlines()[0].strip())
    except (IndexError, ValueError) as error:
        raise RuntimeError(
            f"invalid nvidia-smi memory.used output: {result.stdout!r}"
        ) from error
    return mebibytes * 1024 * 1024


def require_gpu_memory_release(metrics):
    before = metrics["gpu_memory_before_release_bytes"]
    after = metrics["gpu_memory_after_release_bytes"]
    if after >= before:
        raise RuntimeError(
            "framework lifecycle did not release GPU memory: "
            f"before={before} bytes, after={after} bytes"
        )


def timed_http(args, label, endpoint, payload=None):
    """Invoke one lifecycle endpoint and record its elapsed time."""
    print(f"  Dynamo lifecycle: {endpoint}", flush=True)
    started_ns = time.monotonic_ns()
    try:
        response = common.http_json(
            "POST",
            f"{args.base_url.rstrip('/')}/{endpoint}",
            payload,
            args.request_timeout,
        )
    except Exception as error:
        raise RuntimeError(
            f"Dynamo lifecycle request {endpoint} failed: {error}"
        ) from error
    lifecycle_metrics(args)[label] = (
        time.monotonic_ns() - started_ns
    ) // 1000
    return response


class DynamoLifecycleBenchmark(common.ServingBenchmark):
    """Serving benchmark that adds lifecycle spans without changing common.py."""

    def checkpoint_container(self, name, archive, cfg, args):
        result = super().checkpoint_container(name, archive, cfg, args)
        metrics = lifecycle_metrics(args)
        started_ns = metrics.get("_quiesce_started_ns")
        if started_ns is None:
            raise RuntimeError("Dynamo quiesce start was not recorded")
        metrics["quiesce_to_checkpoint_complete_us"] = (
            time.monotonic_ns() - started_ns
        ) // 1000
        return result

    def run_trial(self, cfg, workdir, args, trial_id, keep_running=False):
        if hasattr(args, "_dynamo_lifecycle_metrics"):
            raise RuntimeError("stale Dynamo lifecycle state before trial")
        args._dynamo_lifecycle_metrics = {}
        try:
            result = super().run_trial(
                cfg, workdir, args, trial_id, keep_running
            )
            metrics = dict(lifecycle_metrics(args))
            metrics.pop("_quiesce_started_ns", None)
            missing = [name for name in LIFECYCLE_METRICS[:-1]
                       if not isinstance(metrics.get(name), int)]
            if missing:
                raise RuntimeError(
                    "Dynamo lifecycle did not record: " + ", ".join(missing)
                )
            metrics["recovery_total_us"] = result["restore_to_first_token_us"]
            result.update(metrics)
            result["lifecycle"] = "dynamo-snapshot"
            return result
        finally:
            delattr(args, "_dynamo_lifecycle_metrics")
