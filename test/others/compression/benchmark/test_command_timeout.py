#!/usr/bin/env python3

import contextlib
import importlib.util
import io
from pathlib import Path
import signal
import subprocess
import sys
import time
import unittest
from unittest import mock


ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location(
    "podman_timeout", ROOT / "contrib/compression-benchmark/podman_common.py")
common = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(common)


class CommandTimeoutTests(unittest.TestCase):
    def test_timeout_reaps_children_holding_output_pipes(self):
        # A runtime child inherits Podman's output pipes. Waiting for EOF after
        # killing only the parent would block for the child's entire sleep.
        script = (
            "import subprocess, sys; "
            "print('before runtime', flush=True); "
            "subprocess.run([sys.executable, '-c', 'import time; time.sleep(60)'])"
        )
        started = time.monotonic()
        with contextlib.redirect_stdout(io.StringIO()), self.assertRaises(subprocess.TimeoutExpired) as raised:
            common.run_cmd([sys.executable, "-c", script], timeout=0.5, progress="checkpoint")
        self.assertLess(time.monotonic() - started, 5)
        self.assertIn("before runtime", raised.exception.output)

    def test_interruption_preserves_output_and_kills_group(self):
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.pid = 12345
        interruption = SystemExit(143)
        process.communicate.side_effect = [interruption, ("partial stdout", "partial stderr")]
        with (mock.patch.object(common.subprocess, "Popen", return_value=process) as popen,
              mock.patch.object(common.os, "killpg") as kill,
              self.assertRaises(SystemExit) as raised):
            common.run_cmd(["podman"], timeout=10, progress="restore")
        self.assertIs(raised.exception, interruption)
        self.assertEqual(interruption.output, "partial stdout")
        self.assertEqual(interruption.stderr, "partial stderr")
        self.assertTrue(popen.call_args.kwargs["start_new_session"])
        kill.assert_called_once_with(process.pid, signal.SIGKILL)
        self.assertEqual(process.communicate.call_args, mock.call(timeout=5))

    def test_escaped_child_cannot_make_pipe_drain_unbounded(self):
        process = mock.MagicMock()
        process.__enter__.return_value = process
        process.pid = 12345
        interruption = KeyboardInterrupt()
        process.communicate.side_effect = [
            interruption, subprocess.TimeoutExpired(["podman"], 5, b"captured", b"error"),
        ]
        with (mock.patch.object(common.subprocess, "Popen", return_value=process),
              mock.patch.object(common.os, "killpg"),
              self.assertRaises(KeyboardInterrupt)):
            common.run_cmd(["podman"], timeout=10, progress="restore")
        self.assertEqual(interruption.output, "captured")
        self.assertEqual(interruption.stderr, "error")
        process.stdout.close.assert_called_once()
        process.stderr.close.assert_called_once()


if __name__ == "__main__":
    unittest.main()
