#!/usr/bin/env python3

import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import tempfile
from types import SimpleNamespace
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location(
    "podman_measurements", ROOT / "contrib/compression-benchmark/podman_common.py")
common = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(common)


class BenchmarkMeasurementTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.artifacts = self.root / "artifacts"
        self.artifacts.mkdir()
        self.benchmark = common.ServingBenchmark(SimpleNamespace(display_name="test"), "test")
        self.benchmark.state.trial_artifacts = self.artifacts
        self.args = SimpleNamespace(
            checkpoint_storage="local", archive_compression="none",
            print_stats=True, keep_checkpoint_files=False, command_timeout=17,
            runc_conf="/unused/runc.conf", compress_acceleration=1,
            decompress_threads=None, base_url="http://localhost:30000",
            health_path="/health", wait_seconds=10,
        )
        self.cfg = {"mode": "uncompressed", "block_size": 0}

    def checkpoint_command(self):
        with (mock.patch.object(common, "set_runc_conf_for_cfg"),
              mock.patch.object(common, "podman_operation", return_value=(25, "stats")) as operation):
            result = common.checkpoint_container(
                self.benchmark, "workload", "/unused/export.tar", self.cfg, self.args)
        self.assertEqual(result, (25, "stats"))
        return operation.call_args.args[2]

    def test_local_checkpoint_keeps_images_without_export(self):
        self.benchmark.state.trial_artifacts = None
        command = self.checkpoint_command()
        self.assertEqual(command[:3], [common.PODMAN, "container", "checkpoint"])
        self.assertEqual(command[-1], "workload")
        self.assertIn("--keep", command)
        for option in ("--export", "--compress", "--ignore-volumes"):
            self.assertNotIn(option, command)

    def test_archive_checkpoint_preserves_transport_and_diagnostics(self):
        self.args.checkpoint_storage = "archive"
        self.args.archive_compression = "zstd"
        command = self.checkpoint_command()
        self.assertEqual(command[command.index("--export") + 1], "/unused/export.tar")
        self.assertEqual(command[command.index("--compress") + 1], "zstd")
        self.assertIn("--ignore-volumes", command)
        self.assertIn("--keep", command)

    def restore_command(self):
        with (mock.patch.object(common, "podman_operation", return_value=(25, "stats")) as operation,
              mock.patch.object(common, "wait_health")):
            timing = common.restore_container(
                self.benchmark, "workload", "/unused/export.tar", self.args)
        self.assertEqual(timing["command_us"], 25)
        self.assertEqual(timing["stats"], "stats")
        return operation.call_args.args[2]

    def test_local_restore_uses_existing_container_and_keeps_diagnostics(self):
        command = self.restore_command()
        self.assertEqual(command[:3], [common.PODMAN, "container", "restore"])
        self.assertIn("workload", command)
        self.assertIn("--keep", command)
        for option in ("--import", "--compress", "--ignore-volumes"):
            self.assertNotIn(option, command)

    def test_archive_restore_imports_archive_and_keeps_diagnostics(self):
        self.args.checkpoint_storage = "archive"
        command = self.restore_command()
        self.assertEqual(command[command.index("--import") + 1], "/unused/export.tar")
        self.assertIn("--ignore-volumes", command)
        self.assertIn("--keep", command)
        self.assertNotEqual(command[-1], "workload")

    def test_checkpoint_directory_must_exist(self):
        images = self.root / "checkpoint"
        images.mkdir()
        with mock.patch.object(common, "inspect_container", return_value={
            "State": {"CheckpointPath": str(images)},
        }):
            self.assertEqual(common.checkpoint_directory("workload"), images)
        images.rmdir()
        with (mock.patch.object(common, "inspect_container", return_value={
            "State": {"CheckpointPath": str(images)},
        }), self.assertRaisesRegex(RuntimeError, "no checkpoint directory")):
            common.checkpoint_directory("workload")

    def test_artifact_copy_keeps_logs_and_stats_without_memory_images(self):
        bundle = self.root / "bundle"
        bundle.mkdir()
        files = {
            "dump.log": b"dump details", "stats-dump": b"dump statistics",
            "restore.log": b"restore details", "stats-restore": b"restore statistics",
            "pages-1.img": b"model memory", "inventory.img": b"inventory",
        }
        for filename, data in files.items():
            (bundle / filename).write_bytes(data)
        for phase in ("checkpoint", "restore"):
            self.benchmark.state.operation_outputs[phase] = subprocess.CompletedProcess(
                ["podman"], 0, f"{phase} stdout", f"{phase} stderr")
        with mock.patch.object(common, "inspect_container", return_value={
            "Id": "container-id", "StaticDir": str(bundle),
            "State": {"Status": "exited", "Pid": 0, "Checkpointed": True},
        }):
            for phase in ("checkpoint", "restore"):
                common.save_container_artifacts(self.benchmark, "workload", phase)
        for phase, names in (("checkpoint", ("dump.log", "stats-dump")),
                             ("restore", ("restore.log", "stats-restore"))):
            directory = self.artifacts / phase
            self.assertEqual({path.name for path in directory.iterdir()},
                             {*names, "container-state.json", "podman.stdout", "podman.stderr"})
            for filename in names:
                self.assertEqual((directory / filename).read_bytes(), files[filename])
            state = json.loads((directory / "container-state.json").read_text())
            self.assertEqual(state["id"], "container-id")
            self.assertTrue(state["state"]["Checkpointed"])
            self.assertEqual((directory / "podman.stdout").read_text(), f"{phase} stdout")
            self.assertEqual((directory / "podman.stderr").read_text(), f"{phase} stderr")

    def test_required_missing_statistics_fail_but_failure_collection_is_best_effort(self):
        bundle = self.root / "bundle"
        bundle.mkdir()
        (bundle / "dump.log").write_text("original dump error")
        with mock.patch.object(common, "inspect_container", return_value={
            "StaticDir": str(bundle), "State": {},
        }):
            with self.assertRaisesRegex(RuntimeError, "Missing checkpoint diagnostic: .*stats-dump"):
                common.save_container_artifacts(self.benchmark, "workload", "checkpoint")
            common.save_container_artifacts(self.benchmark, "workload", "checkpoint", required=False)
        self.assertEqual((self.artifacts / "checkpoint" / "dump.log").read_text(),
                         "original dump error")

    def test_reported_log_paths_override_static_and_oci_directories(self):
        for phase, log_key, log_name, stats_name in (
            ("checkpoint", "CheckpointLog", "dump.log", "stats-dump"),
            ("restore", "RestoreLog", "restore.log", "stats-restore"),
        ):
            with self.subTest(phase=phase):
                bundle = self.root / phase
                bundle.mkdir()
                reported_log = bundle / "reported.log"
                reported_log.write_text(f"{phase} details")
                (bundle / stats_name).write_text(f"{phase} statistics")
                info = {
                    "StaticDir": str(self.root / "wrong-static"),
                    "OCIConfigPath": str(self.root / "wrong-oci" / "config.json"),
                    "State": {log_key: str(reported_log)},
                }
                with mock.patch.object(common, "inspect_container", return_value=info):
                    common.save_container_artifacts(self.benchmark, "workload", phase)
                self.assertEqual((self.artifacts / phase / log_name).read_text(),
                                 f"{phase} details")
                self.assertEqual((self.artifacts / phase / stats_name).read_text(),
                                 f"{phase} statistics")

    def test_early_failure_uses_oci_bundle_when_log_path_is_not_recorded(self):
        bundle = self.root / "transient-bundle"
        bundle.mkdir()
        (bundle / "dump.log").write_text("partial checkpoint diagnostic")
        with mock.patch.object(common, "inspect_container", return_value={
            "StaticDir": str(self.root / "persistent-metadata"),
            "OCIConfigPath": str(bundle / "config.json"), "State": {},
        }):
            common.save_container_artifacts(self.benchmark, "workload", "checkpoint", required=False)
        self.assertEqual((self.artifacts / "checkpoint" / "dump.log").read_text(),
                         "partial checkpoint diagnostic")

    def test_missing_reported_log_does_not_select_a_stale_static_log(self):
        (self.root / "dump.log").write_text("stale log")
        with (mock.patch.object(common, "inspect_container", return_value={
            "StaticDir": str(self.root),
            "State": {"CheckpointLog": str(self.root / "missing" / "dump.log")},
        }), self.assertRaisesRegex(RuntimeError, "Missing checkpoint diagnostic: .*missing/dump.log")):
            common.save_container_artifacts(self.benchmark, "workload", "checkpoint")

    def test_local_storage_observation_resolves_the_actual_bundle(self):
        cases = [
            {"State": {"CheckpointPath": "/actual/bundle/checkpoint"}},
            {"OCIConfigPath": "/actual/bundle/config.json", "State": {}},
            {"State": {"CheckpointLog": "/actual/bundle/dump.log"}},
            {"State": {"RestoreLog": "/actual/bundle/restore.log"}},
            {"StaticDir": "/actual/bundle", "State": {}},
        ]
        for info in cases:
            info.setdefault("StaticDir", "/wrong/static")
            with self.subTest(info=info), mock.patch.object(common, "inspect_container", return_value=info):
                self.assertEqual(common.checkpoint_storage_path("workload", "/wrong/workdir", self.args),
                                 Path("/actual/bundle"))

    def test_archive_storage_observation_uses_archive_workdir(self):
        self.args.checkpoint_storage = "archive"
        with mock.patch.object(common, "inspect_container") as inspect:
            self.assertEqual(common.checkpoint_storage_path("workload", "/archive/workdir", self.args),
                             Path("/archive/workdir"))
        inspect.assert_not_called()

    def test_command_timer_excludes_environment_and_diagnostic_collection(self):
        now = [1_000_000_000]
        stages = []

        def environment(*_args):
            now[0] += 2_000_000_000
            stages.append("environment")
            return {"PATH": "/prepared/criu"}

        def command(*_args, **_kwargs):
            now[0] += 5_000_000
            stages.append("command")
            return subprocess.CompletedProcess(["podman"], 0, "raw stats\n", "warning\n")

        def diagnostics(*_args, **_kwargs):
            now[0] += 3_000_000_000
            stages.append("diagnostics")

        with (mock.patch.object(common.time, "monotonic_ns", side_effect=lambda: now[0]),
              mock.patch.object(common, "podman_env", side_effect=environment),
              mock.patch.object(common, "run_cmd", side_effect=command) as run,
              mock.patch.object(common, "save_container_artifacts", side_effect=diagnostics)):
            elapsed, stats = common.podman_operation(
                self.benchmark, "workload", ["podman", "checkpoint"], "checkpoint", self.args)
            # Successful diagnostics are copied later, after the serving
            # readiness measurements, so they cannot inflate those timers.
            self.assertEqual(stages, ["environment", "command"])
            common.save_container_artifacts(self.benchmark, "workload", "checkpoint")
        self.assertEqual(elapsed, 5000)
        self.assertEqual(stats, "raw stats")
        self.assertEqual(stages, ["environment", "command", "diagnostics"])
        run.assert_called_once_with(["podman", "checkpoint"], env={"PATH": "/prepared/criu"},
                                    check=False, timeout=17, progress="checkpoint")
        saved = self.benchmark.state.operation_outputs["checkpoint"]
        self.assertEqual(saved.stdout, "raw stats\n")
        self.assertEqual(saved.stderr, "warning\n")

    def test_command_failure_preserves_output_and_original_error(self):
        failure = subprocess.CompletedProcess(["podman"], 1, "partial stats", "original CRIU failure")
        with (mock.patch.object(common, "podman_env", return_value={}),
              mock.patch.object(common, "run_cmd", return_value=failure),
              mock.patch.object(common, "save_container_artifacts",
                                wraps=common.save_container_artifacts) as save,
              mock.patch.object(common, "inspect_container", side_effect=RuntimeError("container removed")),
              contextlib.redirect_stderr(io.StringIO()),
              self.assertRaisesRegex(RuntimeError, "original CRIU failure")):
            common.podman_operation(self.benchmark, "workload", ["podman"], "restore", self.args)
        save.assert_called_once_with(self.benchmark, "workload", "restore", required=False)
        self.assertEqual((self.artifacts / "restore" / "podman.stdout").read_text(), "partial stats")
        self.assertEqual((self.artifacts / "restore" / "podman.stderr").read_text(), "original CRIU failure")

    def test_timeout_attempts_diagnostics_without_masking_timeout(self):
        timeout = subprocess.TimeoutExpired(["podman"], 17, output="partial output", stderr="blocked")
        with (mock.patch.object(common, "podman_env", return_value={}),
              mock.patch.object(common, "run_cmd", side_effect=timeout),
              mock.patch.object(common, "save_container_artifacts",
                                wraps=common.save_container_artifacts) as save,
              mock.patch.object(common, "inspect_container", side_effect=RuntimeError("container removed")),
              contextlib.redirect_stderr(io.StringIO()),
              self.assertRaises(subprocess.TimeoutExpired) as raised):
            common.podman_operation(self.benchmark, "workload", ["podman"], "restore", self.args)
        self.assertIs(raised.exception, timeout)
        save.assert_called_once_with(self.benchmark, "workload", "restore", required=False)
        self.assertEqual((self.artifacts / "restore" / "podman.stdout").read_text(), "partial output")
        self.assertEqual((self.artifacts / "restore" / "podman.stderr").read_text(), "blocked")

    def test_restore_readiness_includes_resume_but_command_time_does_not(self):
        now = [1_000_000_000]
        order = []

        def restore(*_args):
            now[0] += 25_000
            order.append("restore")
            return 25, "stats"

        def resume(_args):
            now[0] += 10_000_000
            order.append("resume")

        def health(*_args):
            now[0] += 3_000_000
            order.append("health")

        self.benchmark.adapter.after_restore = resume
        with (mock.patch.object(common.time, "monotonic_ns", side_effect=lambda: now[0]),
              mock.patch.object(common, "podman_operation", side_effect=restore),
              mock.patch.object(common, "wait_health", side_effect=health)):
            timing = common.restore_container(
                self.benchmark, "workload", "/unused/export.tar", self.args)
        self.assertEqual(order, ["restore", "resume", "health"])
        self.assertEqual(timing["command_us"], 25)
        self.assertEqual(timing["to_health_us"], 13025)

    def test_nested_podman_statistics_preserve_microseconds_and_criu_fields(self):
        for operation in ("checkpoint", "restore"):
            with self.subTest(operation=operation):
                criu = {"freezing_time": 123, "restore_time": 456, "pages_written": 789}
                document = {
                    f"podman_{operation}_duration": 5_000_000,
                    "container_statistics": [{
                        f"runtime_{operation}_duration": 3_000_000,
                        "criu_statistics": criu,
                    }],
                }
                parsed, runtime, actual_criu = common.parse_podman_stats(
                    json.dumps(document), operation, required=True)
                self.assertEqual(parsed, document)
                self.assertEqual(runtime, 3_000_000)
                self.assertEqual(actual_criu, criu)

    def test_required_podman_statistics_reject_missing_or_ambiguous_container(self):
        cases = ["", "not JSON", "[]", json.dumps({"container_statistics": []}),
                 json.dumps({"container_statistics": [{}, {}]}),
                 json.dumps({"container_statistics": [{
                     "runtime_restore_duration": -1, "criu_statistics": {},
                 }]})]
        for raw in cases:
            with self.subTest(raw=raw), self.assertRaisesRegex(RuntimeError, "Podman restore statistics"):
                common.parse_podman_stats(raw, "restore", required=True)

    def test_measurements_do_not_parse_container_ids_without_print_stats(self):
        self.args.print_stats = False
        result = common.measurement_results(
            self.benchmark, "container-id", "container-id", self.args, self.cfg)
        self.assertIsNone(result["checkpoint_runtime_us"])
        self.assertIsNone(result["restore_runtime_us"])
        self.assertEqual(result["criu_dump_stats"], {})
        self.assertEqual(result["criu_restore_stats"], {})


if __name__ == "__main__":
    unittest.main()
