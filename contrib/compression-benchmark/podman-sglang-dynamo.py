#!/usr/bin/env python3
"""
Podman SGLang CRIU benchmark using Dynamo Snapshot's serving lifecycle.

This opt-in driver follows Dynamo's pause/release and resume/continue ordering
and records the lifecycle spans.  The ordinary podman-sglang.py driver is
intentionally unchanged.
"""

import os
import sys
import time

_BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
if _BENCHMARK_DIR not in sys.path:
    sys.path.insert(0, _BENCHMARK_DIR)

import podman_common as common  # noqa: E402
import podman_dynamo_common as dynamo  # noqa: E402


legacy = dynamo.load_legacy_driver("podman-sglang.py")


class DynamoSglangAdapter(legacy.SglangAdapter):
    default_container_name = "sglang-dynamo-criu-bench"
    temp_prefix = "podman-sglang-dynamo-bench-"

    @staticmethod
    def prepare_args(args):
        legacy.SglangAdapter.prepare_args(args)
        if args.accelerator != "gpu":
            raise RuntimeError("Dynamo SGLang lifecycle requires --accelerator gpu")
        if not args.memory_saver:
            raise RuntimeError("Dynamo SGLang lifecycle requires memory saver")
        dynamo.configure_snapshot_capture_env(args)
        if "--enable-weights-cpu-backup" not in args.sglang_arg:
            args.sglang_arg.append("--enable-weights-cpu-backup")

    @classmethod
    def before_checkpoint(cls, args):
        metrics = dynamo.lifecycle_metrics(args)
        metrics["gpu_memory_before_release_bytes"] = (
            dynamo.gpu_memory_used_bytes(args)
        )
        metrics["_quiesce_started_ns"] = time.monotonic_ns()
        try:
            dynamo.timed_http(
                args, "pause_generation_us", "pause_generation",
                {"mode": "abort"},
            )
            dynamo.timed_http(
                args, "sleep_or_release_us", "release_memory_occupation", {}
            )
        except Exception:
            for endpoint in (
                    "resume_memory_occupation", "continue_generation"):
                try:
                    common.http_json(
                        "POST", f"{args.base_url.rstrip('/')}/{endpoint}", {},
                        args.request_timeout,
                    )
                except Exception:
                    pass
            raise
        metrics["quiesce_us"] = (
            time.monotonic_ns() - metrics["_quiesce_started_ns"]
        ) // 1000
        metrics["gpu_memory_after_release_bytes"] = (
            dynamo.gpu_memory_used_bytes(args)
        )
        dynamo.require_gpu_memory_release(metrics)

    @classmethod
    def after_restore(cls, args):
        metrics = dynamo.lifecycle_metrics(args)
        metrics["gpu_memory_after_runtime_restore_bytes"] = (
            dynamo.gpu_memory_used_bytes(args)
        )
        started_ns = time.monotonic_ns()
        dynamo.timed_http(
            args, "wake_up_us", "resume_memory_occupation", {}
        )
        dynamo.timed_http(
            args, "resume_generation_us", "continue_generation", {}
        )
        metrics["wake_or_resume_us"] = (
            time.monotonic_ns() - started_ns
        ) // 1000
        metrics["gpu_memory_after_wake_bytes"] = (
            dynamo.gpu_memory_used_bytes(args)
        )

    @staticmethod
    def server_summary(args):
        return (
            legacy.SglangAdapter.server_summary(args)
            + ", dynamo-snapshot-lifecycle=on"
        )


_benchmark = dynamo.DynamoLifecycleBenchmark(DynamoSglangAdapter(), __doc__)
main = _benchmark.main


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        sys.exit(f"Error: {error}")
