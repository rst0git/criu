#!/usr/bin/env python3
"""Test timing evidence and report boundaries without containers or GPUs."""

import contextlib
import copy
import errno
import importlib.util
import io
import json
from pathlib import Path
import tempfile
from types import SimpleNamespace
import unittest


ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location(
    "podman_common_report", ROOT / "contrib/compression-benchmark/podman_common.py")
common = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(common)


def statistics(operation, duration=100):
    return {"container_statistics": [{
        f"runtime_{operation}_duration": duration,
        "criu_statistics": {"restore_time" if operation == "restore" else "frozen_time": 70},
    }]}


def cuda_log(operation, backend="driver-api"):
    hook = "checkpoint_devices" if operation == "checkpoint" else "resume_devices_late"
    display = {"driver-api": "Driver API", "cuda-checkpoint": "cuda-checkpoint CLI"}[backend]
    return (
        f"(00.001) cuda_plugin: selected {display} backend for stage 1\n"
        f"(00.002) cuda_plugin: timing backend={backend} phase=init pid=0 ret=0 elapsed_us=10\n"
        f"(00.003) cuda_plugin: timing backend={backend} phase={hook} pid=42 ret=0 elapsed_us=25\n"
        f"(00.004) cuda_plugin: timing backend={backend} phase={hook} pid=43 ret={-errno.ENOTSUP} elapsed_us=5\n"
    )


class ReportTests(unittest.TestCase):
    def test_stats_microseconds_are_preserved(self):
        for raw in (statistics("restore", 123456), json.dumps(statistics("restore", 123456))):
            with self.subTest(raw=raw):
                data, duration, criu = common.parse_podman_stats(raw, "restore", required=True)
                self.assertEqual(duration, 123456)
                self.assertEqual(criu["restore_time"], 70)
                self.assertEqual(len(data["container_statistics"]), 1)

    def test_missing_stats_are_not_zero_timings(self):
        self.assertEqual(common.parse_podman_stats("", "restore"), (None, None, {}))
        with self.assertRaisesRegex(RuntimeError, "Missing Podman restore"):
            common.parse_podman_stats("", "restore", required=True)

    def test_invalid_or_ambiguous_stats_fail(self):
        bad = ["not json", [], {"container_statistics": []},
               {"container_statistics": [{}, {}]}]
        for value in (-1, True, "20", 1.5):
            bad.append(statistics("checkpoint", value))
        missing_criu = statistics("checkpoint")
        del missing_criu["container_statistics"][0]["criu_statistics"]
        bad.append(missing_criu)
        for raw in bad:
            with self.subTest(raw=raw), self.assertRaises(RuntimeError):
                common.parse_podman_stats(raw, "checkpoint")

    def test_cuda_includes_unsupported_process_cost(self):
        records = common.parse_cuda_timings(cuda_log("checkpoint"), "checkpoint", "driver-api", True)
        self.assertEqual([record["ret"] for record in records], [0, 0, -errno.ENOTSUP])
        self.assertEqual(sum(record["elapsed_us"] for record in records), 40)
        self.assertTrue(all(record["operation"] == "checkpoint" for record in records))

    def test_cuda_backend_mismatch_and_missing_phases_fail(self):
        for log in (cuda_log("restore", "cuda-checkpoint"), "",
                    cuda_log("restore").replace("phase=resume_devices_late", "phase=other"),
                    cuda_log("restore").replace("elapsed_us=25", "elapsed_us=bad")):
            with self.subTest(log=log), self.assertRaises(RuntimeError):
                common.parse_cuda_timings(log, "restore", "driver-api", True)

    def test_measurement_results_save_evidence_separate_from_wall_time(self):
        with tempfile.TemporaryDirectory() as directory:
            artifacts = Path(directory)
            for operation, name in (("checkpoint", "dump.log"), ("restore", "restore.log")):
                (artifacts / operation).mkdir()
                (artifacts / operation / name).write_text(cuda_log(operation))
            benchmark = SimpleNamespace(state=SimpleNamespace(trial_artifacts=artifacts))
            args = SimpleNamespace(print_stats=True, cuda_timings=True)
            result = common.measurement_results(
                benchmark, statistics("checkpoint", 100), statistics("restore", 200),
                args, {"cuda_backend": "driver-api"})
            self.assertEqual(result["checkpoint_runtime_us"], 100)
            self.assertEqual(result["restore_runtime_us"], 200)
            self.assertEqual(len(result["cuda_timings"]), 6)
            self.assertNotIn("restore_wall_us", result)
            saved = json.loads((artifacts / "restore/podman-stats.json").read_text())
            self.assertEqual(saved, statistics("restore", 200))

    def test_disabling_timing_still_requires_backend_identity(self):
        log = "cuda_plugin: selected Driver API backend for stage 1\n"
        self.assertEqual(common.parse_cuda_timings(log, "restore", "driver-api", False), [])
        with self.assertRaisesRegex(RuntimeError, "backend evidence"):
            common.parse_cuda_timings(log, "restore", "cuda-checkpoint", False)

    def test_cuda_cli_display_name_is_normalized(self):
        records = common.parse_cuda_timings(
            cuda_log("restore", "cuda-checkpoint"), "restore", "cuda-checkpoint", True)
        self.assertTrue(all(record["backend"] == "cuda-checkpoint" for record in records))

    def test_no_print_stats_accepts_container_id_stdout(self):
        benchmark = SimpleNamespace(state=SimpleNamespace(trial_artifacts=None))
        result = common.measurement_results(
            benchmark, "container-id", "container-id", SimpleNamespace())
        self.assertIsNone(result["checkpoint_runtime_us"])
        self.assertIsNone(result["restore_runtime_us"])
        self.assertEqual(result["criu_restore_stats"], {})

    def test_report_labels_single_trial_and_voice_packet_boundary(self):
        trial = {"valid": True, "checkpoint_size": 1024 ** 3,
                 "application_prepare_us": 100, "application_resume_us": 150,
                 "checkpoint_wall_us": 1000, "restore_wall_us": 2000,
                 "checkpoint_runtime_us": 900, "restore_runtime_us": 1700,
                 "restore_to_health_us": 2100, "restore_to_first_audio_packet_us": 3000,
                 "post_request_us": 200,
                 "cuda_timings": common.parse_cuda_timings(cuda_log("restore"), "restore", "driver-api")}
        benchmark = SimpleNamespace(adapter=SimpleNamespace(heading="VOICECHAT"))
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            common.report(benchmark, {"Driver": [trial]}, ["Driver"])
        report = output.getvalue()
        for text in ("INCONCLUSIVE", "n=1", "1.00 GiB", "Checkpoint OCI runtime",
                     "Application checkpoint preparation", "Application resume",
                     "Restore to health", "Restore to first audio packet", "unsupported=1",
                     "nested; do not add"):
            self.assertIn(text, report)
        self.assertNotIn("Restore to first token", report)

    def test_report_range_and_legacy_storage_field(self):
        trials = [{"valid": True, "archive_size": 1024 ** 3, "restore_wall_us": value}
                  for value in (1000, 2000, 3000, 4000)]
        benchmark = SimpleNamespace(adapter=SimpleNamespace(heading="SGLANG"))
        original = copy.deepcopy(trials)
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            common.report(benchmark, {"Driver": trials}, ["Driver"])
        self.assertIn("2.5 ms [1.0 ms, 4.0 ms] (n=4)", output.getvalue())
        self.assertIn("unavailable (n=0)", output.getvalue())
        self.assertNotIn("INCONCLUSIVE", output.getvalue())
        self.assertEqual(trials, original)

    def test_pairs_use_rotated_trial_rounds_and_skip_missing_measurements(self):
        first = [{"trial": 5, "valid": True, "restore_runtime_us": 2000},
                 {"trial": 4, "valid": True, "restore_runtime_us": 1000},
                 {"trial": 8, "valid": True, "restore_runtime_us": 3000}]
        second = [{"trial": 3, "valid": True, "restore_runtime_us": 1200},
                  {"trial": 6, "valid": True, "restore_runtime_us": None},
                  {"trial": 7, "valid": True, "restore_runtime_us": 2900}]
        self.assertEqual(common.paired_runtime_differences(first, second, "restore_runtime_us"),
                         [200, -100])

    def test_pairing_does_not_guess_without_trial_identity(self):
        trials = [{"valid": True, "restore_runtime_us": 1000}]
        self.assertEqual(common.paired_runtime_differences(trials, trials, "restore_runtime_us"), [])

    def test_paired_report_marks_crossing_zero_and_sparse_metrics(self):
        first, second = [], []
        for index, delta in enumerate((-2000, -1000, 1000, 2000), 1):
            first.append({"trial": index * 2 + 1, "valid": True,
                          "restore_runtime_us": 5000, "checkpoint_runtime_us": 5000})
            second.append({"trial": index * 2 + 2, "valid": True,
                           "restore_runtime_us": 5000 + delta,
                           "checkpoint_runtime_us": 5500 if index < 4 else None})
        output = io.StringIO()
        benchmark = SimpleNamespace(adapter=SimpleNamespace(heading="SGLANG"))
        with contextlib.redirect_stdout(output):
            common.report(benchmark, {"Driver": first, "CLI": second}, ["Driver", "CLI"])
        report = output.getvalue().split("PAIRED OCI DIFFERENCES:")[1]
        self.assertIn("CLI minus Driver", report)
        self.assertIn("Checkpoint: +0.5 ms [+0.5 ms, +0.5 ms] (n=3)", report)
        self.assertIn("fewer than four complete pairs", report)
        self.assertIn("Restore: 0.0 ms [-2.0 ms, +2.0 ms] (n=4)", report)
        self.assertIn("paired difference range includes zero", report)
        self.assertIn("not a significance test", report)

    def test_consistent_four_pairs_do_not_claim_significance(self):
        first = [{"trial": index * 2 + 1, "valid": True,
                  "restore_runtime_us": 2000000, "checkpoint_runtime_us": 2000000}
                 for index in range(1, 5)]
        second = [{**trial, "trial": trial["trial"] + 1,
                   "restore_runtime_us": 1000000, "checkpoint_runtime_us": 1500000}
                  for trial in first]
        output = io.StringIO()
        benchmark = SimpleNamespace(adapter=SimpleNamespace(heading="SGLANG"))
        with contextlib.redirect_stdout(output):
            common.report(benchmark, {"Driver": first, "CLI": second}, ["Driver", "CLI"])
        report = output.getvalue()
        self.assertIn("Restore: -1.000 s [-1.000 s, -1.000 s] (n=4)", report)
        self.assertNotIn("INCONCLUSIVE", report)
        self.assertIn("not a significance test", report)


if __name__ == "__main__":
    unittest.main()
