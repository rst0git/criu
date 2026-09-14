#!/usr/bin/env python3

import argparse
import contextlib
import importlib.util
import io
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[4]
BENCHMARK = ROOT / "contrib/compression-benchmark"
SPEC = importlib.util.spec_from_file_location("podman_voicechat", BENCHMARK / "podman-voicechat.py")
driver = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(driver)


def parse_arguments(extra=()):
    # Stop the shared entry point before host inspection or container actions.
    original = argparse.ArgumentParser.parse_args
    captured = []

    class Parsed(Exception):
        pass

    def capture(parser, *args, **kwargs):
        captured.append(original(parser, *args, **kwargs))
        raise Parsed

    with mock.patch.object(argparse.ArgumentParser, "parse_args", capture):
        try:
            driver.main([
                "--image", "example/voicechat@sha256:" + "a" * 64,
                "--model-repo", "/models", "--audio", "/speech.wav",
                "--artifacts-dir", "/artifacts", "--criu-libdir", "/plugins",
                "--json", "/results.json", *extra,
            ])
        except Parsed:
            pass
    return captured[0]


class VoiceChatDriverTests(unittest.TestCase):
    def test_launch_job_owns_server_entrypoint(self):
        args = parse_arguments()
        args.cuda_checkpoint_binary = "/usr/bin/cuda-checkpoint"
        adapter = driver.VoiceChatAdapter()
        adapter.normalize_args(argparse.ArgumentParser(), args)
        self.assertEqual(args.iterations, 1)
        self.assertEqual(args.cuda_backends, ["driver-api", "cuda-checkpoint"])
        self.assertTrue(args.cuda_checkpoint_launch_job)
        command = driver.VoiceChatBenchmark(adapter, "test").build_container_cmd("test", args)
        image_index = command.index(args.image)
        self.assertEqual(command[image_index - 2:image_index],
                         ["--entrypoint", "/usr/local/bin/cuda-checkpoint"])
        self.assertEqual(command[image_index + 1:], ["--launch-job", "/s2s/run_s2s_server.sh"])
        self.assertIn("/models:/data/models:ro", command)
        self.assertIn("NIM_HTTP_API_PORT=9000", command)
        self.assertNotIn("--enable-memory-saver", command)

    def test_rejects_unpinned_image_and_conflicting_port(self):
        for extra in (["--image", "example/voicechat:latest"], ["--port", "8000"],
                      ["--cuda-backends", "driver-api", "driver-api"]):
            with self.subTest(extra=extra), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit):
                    driver.VoiceChatAdapter.normalize_args(argparse.ArgumentParser(),
                                                          parse_arguments(extra))

    def test_checks_all_triton_ports_before_launch(self):
        benchmark = driver.VoiceChatBenchmark(driver.VoiceChatAdapter(), "test")
        with (mock.patch.object(driver.common, "ensure_server_port_available") as check,
              mock.patch.object(driver.common.ServingBenchmark, "start_container") as start):
            benchmark.start_container("test", SimpleNamespace())
        self.assertEqual(check.call_args_list, [mock.call(8000), mock.call(8001), mock.call(8002)])
        start.assert_called_once()

    def run_trial(self, after_transcript="Say hello.", replay_error=None):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        root = Path(temporary.name)
        artifacts = root / "speech"
        artifacts.mkdir()
        args = SimpleNamespace(container_name="voicechat", archive_compression="none",
                               artifacts_dir=str(artifacts), base_url="http://localhost:9000",
                               audio="input.wav", request_timeout=180, warmup_requests=0)
        benchmark = driver.VoiceChatBenchmark(driver.VoiceChatAdapter(), "test")
        order = []

        def start(name, _args):
            benchmark.state.started_containers.add(name)
            order.append("start")
            return {"started_ns": 100, "to_health_us": 2}

        def checkpoint(_name, archive, _cfg, _args):
            order.append("checkpoint")
            Path(archive).write_bytes(b"archive")
            return 3, "checkpoint stats"

        def restore(name, _archive, _args):
            order.append("restore")
            benchmark.state.started_containers.add(name)
            return {"started_ns": 200, "command_us": 4, "to_health_us": 5, "stats": "restore stats"}

        def replay(_url, _audio, _timeout, _started_ns, prefix):
            order.append(prefix.name)
            if replay_error:
                raise RuntimeError(replay_error)
            return {"valid": True, "user_transcript": "Say hello." if prefix.name == "before" else after_transcript,
                    "operation_to_first_audio_packet_us": 10, "operation_to_session_complete_us": 20,
                    "request_us": 30, "transcript": "sampled reply"}

        patches = [mock.patch.object(benchmark, "start_container", side_effect=start),
                   mock.patch.object(benchmark, "checkpoint_container", side_effect=checkpoint),
                   mock.patch.object(benchmark, "restore_container", side_effect=restore),
                   mock.patch.object(driver, "replay_audio", side_effect=replay),
                   mock.patch.object(driver.common, "verify_archive_compression", return_value="none"),
                   mock.patch.object(driver.common, "remove_container", side_effect=lambda _name: order.append("remove"))]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            try:
                result = benchmark.run_trial({"mode": "uncompressed"}, root, args, 1)
            except RuntimeError:
                self.last_order = order
                raise
        self.assertFalse(benchmark.state.started_containers)
        return result, order

    def test_roundtrip_retains_speech_results_and_oci_stats(self):
        result, order = self.run_trial()
        self.assertEqual(order, ["start", "before", "checkpoint", "remove", "restore", "after", "remove"])
        self.assertTrue(result["valid"])
        self.assertEqual(result["gpu_state"], "live")
        self.assertEqual(result["cache_policy"], "uncontrolled")
        self.assertEqual(result["checkpoint_stats"], "checkpoint stats")
        self.assertEqual(result["restore_stats"], "restore stats")
        self.assertIn("restore_to_first_audio_packet_us", result)
        self.assertNotIn("restore_to_first_token_us", result)

    def test_changed_input_transcription_fails_trial(self):
        with self.assertRaisesRegex(RuntimeError, "transcription changed"):
            self.run_trial(after_transcript="Corrupted input.")

    def test_invalid_initial_speech_does_not_checkpoint(self):
        with self.assertRaisesRegex(RuntimeError, "silent audio"):
            self.run_trial(replay_error="silent audio")
        self.assertEqual(self.last_order, ["start", "before"])


if __name__ == "__main__":
    unittest.main()
