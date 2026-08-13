#!/usr/bin/env python3
"""
Podman vLLM CRIU benchmark using Dynamo Snapshot's serving lifecycle.

This opt-in driver pauses generation, enters vLLM sleep level 1, checkpoints,
then wakes the engine and resumes generation after restore.  The ordinary
podman-vllm.py driver is intentionally unchanged.
"""

import os
import sys
import time

_BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
if _BENCHMARK_DIR not in sys.path:
    sys.path.insert(0, _BENCHMARK_DIR)

import podman_common as common  # noqa: E402
import podman_dynamo_common as dynamo  # noqa: E402


legacy = dynamo.load_legacy_driver("podman-vllm.py")


class DynamoVllmAdapter(legacy.VllmAdapter):
    default_container_name = "vllm-dynamo-criu-bench"
    temp_prefix = "podman-vllm-dynamo-bench-"

    @staticmethod
    def add_server_arguments(parser):
        legacy.VllmAdapter.add_server_arguments(parser)
        parser.add_argument(
            "--vllm-sleep-level",
            choices=(1, 2),
            default=1,
            type=int,
            help="vLLM sleep level (default: 1, matching Dynamo Snapshot)",
        )

    @staticmethod
    def prepare_args(args):
        legacy.VllmAdapter.prepare_args(args)
        if args.accelerator != "gpu":
            raise RuntimeError("Dynamo vLLM lifecycle requires --accelerator gpu")
        dynamo.configure_snapshot_capture_env(
            args, {"VLLM_SERVER_DEV_MODE": "1"}
        )
        if "--enable-sleep-mode" not in args.vllm_arg:
            args.vllm_arg.append("--enable-sleep-mode")

    @staticmethod
    def _wait_for_sleep_state(args, expected):
        deadline = time.monotonic() + args.request_timeout
        while True:
            response = common.http_json(
                "GET", f"{args.base_url.rstrip('/')}/is_sleeping", None,
                args.request_timeout,
            )
            actual = (response.get("is_sleeping")
                      if isinstance(response, dict) else response)
            if actual is expected:
                return
            if time.monotonic() >= deadline:
                raise RuntimeError(
                    "timed out waiting for vLLM sleep state "
                    f"{expected}: {response!r}"
                )
            time.sleep(0.1)

    @classmethod
    def before_checkpoint(cls, args):
        metrics = dynamo.lifecycle_metrics(args)
        metrics["gpu_memory_before_release_bytes"] = (
            dynamo.gpu_memory_used_bytes(args)
        )
        metrics["_quiesce_started_ns"] = time.monotonic_ns()
        try:
            dynamo.timed_http(
                args, "pause_generation_us", "pause?mode=abort"
            )
            sleep_started_ns = time.monotonic_ns()
            dynamo.timed_http(
                args,
                "sleep_or_release_us",
                f"sleep?level={args.vllm_sleep_level}&mode=abort",
            )
            cls._wait_for_sleep_state(args, True)
            metrics["sleep_or_release_us"] = (
                time.monotonic_ns() - sleep_started_ns
            ) // 1000
        except Exception:
            for endpoint in ("wake_up", "resume"):
                try:
                    common.http_json(
                        "POST", f"{args.base_url.rstrip('/')}/{endpoint}",
                        None, args.request_timeout,
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
        wake_started_ns = time.monotonic_ns()
        dynamo.timed_http(args, "wake_up_us", "wake_up")
        cls._wait_for_sleep_state(args, False)
        metrics["wake_up_us"] = (
            time.monotonic_ns() - wake_started_ns
        ) // 1000
        dynamo.timed_http(args, "resume_generation_us", "resume")
        metrics["wake_or_resume_us"] = (
            time.monotonic_ns() - started_ns
        ) // 1000
        metrics["gpu_memory_after_wake_bytes"] = (
            dynamo.gpu_memory_used_bytes(args)
        )

    @staticmethod
    def server_summary(args):
        return (
            legacy.VllmAdapter.server_summary(args)
            + f", dynamo-snapshot-lifecycle=on, sleep-level={args.vllm_sleep_level}"
        )


_benchmark = dynamo.DynamoLifecycleBenchmark(DynamoVllmAdapter(), __doc__)
main = _benchmark.main


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        sys.exit(f"Error: {error}")
