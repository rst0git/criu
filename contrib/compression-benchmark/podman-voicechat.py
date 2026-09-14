#!/usr/bin/env python3
"""Compare CRIU CUDA backends with NVIDIA's realtime VoiceChat container.

Replay a fixed WAV file in a fresh speech session before and after restoring
the container. This saves live CUDA state: no SGLang memory-release hooks run.
Output validation is functional, with an additional exact comparison of the
input transcription. The realtime API does not expose deterministic sampling.
"""

import hashlib
import os
from pathlib import Path
import re
import shutil
from statistics import median
import sys
import wave

_BENCHMARK_DIR = os.path.dirname(os.path.abspath(__file__))
if _BENCHMARK_DIR not in sys.path:
    sys.path.insert(0, _BENCHMARK_DIR)

import podman_common as common  # noqa: E402
from voicechat_client import replay_audio  # noqa: E402


MODEL = "nvidia/NVIDIA-NemotronLabs-VoiceChat-11B"
MODEL_REVISION = "a4c40ca5b4fe77db13e9840ca4a2b91becf030c8"


def file_sha256(path):
    digest = hashlib.sha256()
    with open(path, "rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


class VoiceChatAdapter:
    key = "voicechat"
    display_name = "VoiceChat"
    heading = "VOICECHAT"
    default_container_name = "voicechat-criu-bench"
    temp_prefix = "podman-voicechat-bench-"

    @staticmethod
    def add_image_arguments(parser):
        parser.add_argument("--image", required=True,
                            help="NVIDIA VoiceChat image pinned by SHA-256 digest")

    @staticmethod
    def add_model_arguments(parser):
        parser.add_argument("--model-repo", required=True,
                            help="Prepared Triton model repository mounted at /data/models")
        parser.add_argument("--model-revision", default=MODEL_REVISION)
        parser.set_defaults(model=MODEL)

    @staticmethod
    def add_resource_arguments(parser):
        pass

    @staticmethod
    def add_request_arguments(parser):
        parser.add_argument("--audio", required=True,
                            help="Fixed 24 kHz mono PCM16 WAV; 20 seconds of silence are appended")
        parser.add_argument("--artifacts-dir", required=True,
                            help="New directory for persistent speech artifacts")

    @staticmethod
    def add_server_arguments(parser):
        parser.add_argument("--cuda-backends", nargs="+",
                            choices=["driver-api", "cuda-checkpoint"],
                            default=["driver-api", "cuda-checkpoint"])
        parser.add_argument("--cuda-checkpoint-binary", default="cuda-checkpoint")
        parser.set_defaults(port=9000, health_path="/v1/realtime/health",
                            modes=["uncompressed"], iterations=1,
                            shm_size="8g", print_stats=True,
                            cuda_checkpoint_launch_job=True)

    @staticmethod
    def normalize_args(parser, args):
        if args.accelerator != "gpu" or not args.criu_libdir:
            parser.error("VoiceChat requires GPU and --criu-libdir")
        if args.model != MODEL:
            parser.error(f"This adapter serves only {MODEL}")
        if args.port in (8000, 8001, 8002):
            parser.error("--port must differ from Triton's fixed ports 8000, 8001 and 8002")
        if not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}", args.image):
            parser.error("--image must include a full sha256 digest")
        if not re.fullmatch(r"[0-9a-f]{40}", args.model_revision):
            parser.error("--model-revision must be a full lowercase commit hash")
        if len(set(args.cuda_backends)) != len(args.cuda_backends):
            parser.error("--cuda-backends must not contain duplicates")
        if args.request_timeout <= 0:
            parser.error("--request-timeout must be positive")
        if args.warmup_requests < 0:
            parser.error("--warmup-requests must be nonnegative")
        if not args.json:
            parser.error("--json is required to preserve comparison results")

    @staticmethod
    def prepare_args(args):
        # Fail before container launch or changing the host CRIU configuration.
        try:
            import websockets.asyncio.client  # noqa: F401
        except ImportError as error:
            raise RuntimeError("Install websockets>=14 in the benchmark Python environment") from error
        if os.path.exists(args.json):
            raise RuntimeError(f"Results already exist: {args.json}")
        binary = shutil.which(args.cuda_checkpoint_binary)
        if not binary:
            raise RuntimeError(f"CUDA checkpoint launcher not found: {args.cuda_checkpoint_binary}")
        args.cuda_checkpoint_binary = os.path.abspath(binary)
        args.model_repo = os.path.abspath(args.model_repo)
        if not os.path.isdir(os.path.join(args.model_repo, "nemotron-voicechat")):
            raise RuntimeError("--model-repo must contain the converted nemotron-voicechat repository")
        args.audio = os.path.abspath(args.audio)
        with wave.open(args.audio, "rb") as source:
            if (source.getframerate(), source.getnchannels(), source.getsampwidth()) != (24000, 1, 2):
                raise RuntimeError("--audio must be a 24 kHz mono PCM16 WAV")
            if source.getnframes() == 0:
                raise RuntimeError("--audio contains no samples")
            if source.getnframes() / 24000 + 20 >= args.request_timeout:
                raise RuntimeError("--request-timeout must exceed the recording duration plus 20 seconds")
        args.audio_sha256 = file_sha256(args.audio)
        args.artifacts_dir = os.path.abspath(args.artifacts_dir)
        os.mkdir(args.artifacts_dir)
        # Retain a digest of the actual converted inputs, not just the HF name.
        print("  Hashing converted VoiceChat model files (outside timed trials)", flush=True)
        args.model_files = {}
        for path in sorted(Path(args.model_repo).rglob("*")):
            if path.is_file():
                args.model_files[str(path.relative_to(args.model_repo))] = file_sha256(path)
        if not args.model_files:
            raise RuntimeError("Converted model repository contains no files")

    @staticmethod
    def extra_podman_args(args):
        return [
            "--volume", f"{args.model_repo}:/data/models:ro",
            "--volume", f"{args.cuda_checkpoint_binary}:/usr/local/bin/cuda-checkpoint:ro",
            "--env", f"NIM_HTTP_API_PORT={args.port}",
        ]

    @staticmethod
    def server_argv(args):
        return [
            "--entrypoint", "/usr/local/bin/cuda-checkpoint", args.image,
            "--launch-job", "/s2s/run_s2s_server.sh",
        ]

    @staticmethod
    def server_summary(args):
        return "NVIDIA realtime container, live CUDA state, launch-job=on"

    @staticmethod
    def request_summary(args):
        return f"audio={args.audio}, functional speech validation, warmup_requests={args.warmup_requests}"


class VoiceChatBenchmark(common.ServingBenchmark):
    def start_container(self, name, args):
        # The image's launcher probes fixed Triton ports as well as the API.
        for port in (8000, 8001, 8002):
            common.ensure_server_port_available(port)
        return super().start_container(name, args)

    def run_trial(self, cfg, workdir, args, trial_id, keep_running=False):
        name = f"{args.container_name}-{os.getpid()}-{trial_id}"
        archive = os.path.join(workdir, name + ".tar")
        if args.archive_compression != "none":
            archive += ".gz" if args.archive_compression == "gzip" else ".zst"
        artifacts = Path(args.artifacts_dir) / f"trial-{trial_id}"
        artifacts.mkdir()

        def replay(label, started_ns):
            print(f"  VoiceChat audio replay: {label}", flush=True)
            return replay_audio(args.base_url, args.audio, args.request_timeout,
                                started_ns, artifacts / label)

        cold = self.start_container(name, args)
        before = replay("before", cold["started_ns"])
        cold_first_audio_packet_us = before["operation_to_first_audio_packet_us"]
        for index in range(args.warmup_requests):
            before = replay(f"warmup-{index + 1}", cold["started_ns"])
        # replay_audio waits for session.end and disconnects before returning.
        checkpoint_us, checkpoint_stats = self.checkpoint_container(name, archive, cfg, args)
        compression = common.verify_archive_compression(archive, cfg)
        common.remove_container(name)
        self.state.started_containers.discard(name)
        restored = self.restore_container(name, archive, args)
        after = replay("after", restored["started_ns"])
        if before["user_transcript"].strip() != after["user_transcript"].strip():
            raise RuntimeError(f"Input audio transcription changed after restore; see {artifacts}")
        if keep_running:
            self.state.started_containers.discard(name)
        else:
            common.remove_container(name)
            self.state.started_containers.discard(name)
        return {
            "archive_size": os.path.getsize(archive),
            "inventory_compress_mode": compression,
            "checkpoint_wall_us": checkpoint_us,
            "restore_wall_us": restored["command_us"],
            "server_start_to_health_us": cold["to_health_us"],
            "cold_start_to_first_audio_packet_us": cold_first_audio_packet_us,
            "restore_to_health_us": restored["to_health_us"],
            "restore_to_first_audio_packet_us": after["operation_to_first_audio_packet_us"],
            "restore_to_session_complete_us": after["operation_to_session_complete_us"],
            "pre_request_us": before["request_us"],
            "post_request_us": after["request_us"],
            "checkpoint_stats": checkpoint_stats,
            "restore_stats": restored["stats"],
            "validation": "functional speech and matching input transcription",
            "before": before,
            "after": after,
            "valid": True,
            "cache_policy": "uncontrolled",
            "gpu_state": "live",
            "framework": self.adapter.key,
            "artifacts": str(artifacts),
            "container_name": name if keep_running else None,
        }

    def report(self, results_by_cfg, order):
        super().report(results_by_cfg, order)
        print("\n  Restore to first audio packet (median, includes health and audio replay):")
        for label in order:
            timing = median(r["restore_to_first_audio_packet_us"] for r in results_by_cfg[label])
            print(f"  {label}: {common.format_duration(timing)}")
        print("  Validation checks speech output and input transcription; generated audio may differ.")


def main(argv=None):
    VoiceChatBenchmark(VoiceChatAdapter(), __doc__).main(argv)


if __name__ == "__main__":
    try:
        main()
    except (OSError, RuntimeError) as error:
        sys.exit(f"Error: {error}")
