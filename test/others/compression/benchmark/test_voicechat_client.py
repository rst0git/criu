#!/usr/bin/env python3

import asyncio
import base64
import importlib.util
import json
from pathlib import Path
import struct
import sys
import tempfile
import time
from types import SimpleNamespace
import unittest
from unittest import mock
import wave


ROOT = Path(__file__).resolve().parents[4]
SPEC = importlib.util.spec_from_file_location(
    "voicechat_client", ROOT / "contrib/compression-benchmark/voicechat_client.py")
client = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(client)


class FakeConnection:
    def __init__(self, events, session_update=None):
        self.events = events
        self.queue = asyncio.Queue()
        self.queue.put_nowait(json.dumps({"type": "session.created"}))
        self.sent = []
        self.closed = False
        self.session_update = session_update

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        self.closed = True

    async def send(self, message):
        event = json.loads(message)
        self.sent.append(event)
        if event["type"] == "session.update":
            session = (event["session"] if self.session_update is None
                       else self.session_update)
            self.queue.put_nowait(json.dumps({"type": "session.updated", "session": session}))
        elif event["type"] == "input_audio_buffer.append":
            for response in self.events:
                self.queue.put_nowait(json.dumps(response))
            self.events = []
        elif event["type"] == "session.close":
            self.queue.put_nowait(json.dumps({"type": "session.end"}))

    async def recv(self):
        return await self.queue.get()


def complete_response():
    return [
        {"type": "response.created", "response": {"id": "response-1"}},
        {"type": "response.output_audio.delta",
         "delta": base64.b64encode(struct.pack("<hh", 42, -42)).decode()},
        {"type": "response.output_audio_transcript.done", "transcript": "Hello."},
        {"type": "conversation.item.input_audio_transcription.completed",
         "transcript": "Say hello."},
        {"type": "response.done", "response": {"id": "response-1", "status": "completed"}},
    ]


class VoiceChatClientTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.wav = Path(self.directory.name) / "input.wav"
        self.prefix = Path(self.directory.name) / "output"
        with wave.open(str(self.wav), "wb") as output:
            output.setnchannels(1)
            output.setsampwidth(2)
            output.setframerate(24000)
            output.writeframes(struct.pack("<h", 17) * 1920)

    def run_replay(self, events, timeout=1, session_update=None):
        self.connection = FakeConnection(events, session_update=session_update)
        connector = mock.Mock(return_value=self.connection)
        original_sleep = asyncio.sleep

        async def yield_without_delay(_delay):
            await original_sleep(0)

        with (mock.patch.dict(sys.modules, {"websockets": SimpleNamespace(connect=connector)}),
              mock.patch.object(client.asyncio, "sleep", yield_without_delay)):
            result = client.replay_audio("http://localhost:9000", self.wav, timeout,
                                         time.perf_counter_ns(), self.prefix)
        self.assertEqual(connector.call_args.args[0], "ws://localhost:9000/v1/realtime")
        return result

    def test_replays_audio_with_silence_and_closes_session(self):
        result = self.run_replay(complete_response())
        self.assertTrue(result["valid"])
        self.assertEqual(result["validation"], "functional")
        self.assertEqual(result["transcript"], "Hello.")
        self.assertEqual(result["user_transcript"], "Say hello.")
        self.assertTrue(result["response_completed"])
        self.assertTrue(self.connection.closed)
        self.assertEqual(self.connection.sent[0]["session"]["tools"], [])
        self.assertEqual(self.connection.sent[-1]["type"], "session.close")
        chunks = [base64.b64decode(event["audio"]) for event in self.connection.sent
                  if event["type"] == "input_audio_buffer.append"]
        self.assertEqual(len(chunks), 251)
        self.assertEqual(len(b"".join(chunks)), (1920 + 24000 * 20) * 2)
        self.assertTrue(all(not any(chunk) for chunk in chunks[1:]))
        for field in ("request_us", "request_to_first_audio_packet_us",
                      "operation_to_first_audio_packet_us", "operation_to_session_complete_us"):
            self.assertGreaterEqual(result[field], 0)
        with wave.open(result["audio_path"], "rb") as output:
            self.assertEqual(output.getframerate(), 24000)
            self.assertEqual(output.readframes(2), struct.pack("<hh", 42, -42))
        events = json.loads(Path(result["events_path"]).read_text())
        audio_event = next(event for event in events if event["type"].endswith("audio.delta"))
        self.assertNotIn("delta", audio_event)
        self.assertEqual(audio_event["audio_bytes"], 4)

    def test_generated_response_does_not_require_exact_text(self):
        events = complete_response()
        events[2]["transcript"] = "A different sampled reply."
        result = self.run_replay(events)
        self.assertTrue(result["valid"])

    def test_rejects_unsupported_negotiated_audio_before_sending(self):
        for direction, audio_format in (
            ("input", {"type": "audio/pcm", "rate": 16000}),
            ("output", {"type": "audio/pcm", "rate": 22050}),
            ("output", {"type": "audio/opus", "rate": 24000}),
        ):
            with self.subTest(direction=direction, audio_format=audio_format):
                session = {"audio": {
                    side: {"format": {"type": "audio/pcm", "rate": 24000}}
                    for side in ("input", "output")
                }}
                session["audio"][direction]["format"] = audio_format
                with self.assertRaisesRegex(RuntimeError, f"PCM16 {direction} audio"):
                    self.run_replay(complete_response(), session_update=session)
                self.assertEqual(len(self.connection.sent), 1)
                self.assertTrue(self.connection.closed)
                saved = json.loads(Path(str(self.prefix) + ".json").read_text())
                self.assertFalse(saved["valid"])
                self.assertIn(str(audio_format), saved["error"])

    def test_rejects_missing_negotiated_audio_format(self):
        with self.assertRaisesRegex(RuntimeError, "effective session: {}"):
            self.run_replay(complete_response(), session_update={})
        self.assertEqual(len(self.connection.sent), 1)
        self.assertTrue(self.connection.closed)

    def test_rejects_missing_or_silent_outputs_and_incomplete_response(self):
        cases = [
            ("agent transcript", lambda events: events.pop(2)),
            ("user transcript", lambda events: events.pop(3)),
            ("non-silent audio", lambda events: events[1].update(delta="AAAAAA==")),
            ("complete response", lambda events: events.pop()),
            ("did not complete", lambda events: events[-1]["response"].update(status="failed")),
        ]
        for reason, change in cases:
            with self.subTest(reason=reason):
                events = complete_response()
                change(events)
                with self.assertRaisesRegex(RuntimeError, reason):
                    self.run_replay(events)
                saved = json.loads(Path(str(self.prefix) + ".json").read_text())
                self.assertFalse(saved["valid"])
                self.assertIn(reason, saved["error"])
                self.assertTrue(self.connection.closed)

    def test_server_errors_and_tools_are_not_ignored(self):
        for event, reason in (
            ({"type": "error", "error": {"message": "broken"}}, "server error"),
            ({"type": "response.function_call_arguments.done"}, "requested a tool"),
            ({"type": "response.output_audio.delta", "delta": "!"}, "invalid PCM"),
            ({"type": "response.output_audio.delta", "delta": "AA=="}, "incomplete PCM16"),
        ):
            with self.subTest(event=event):
                with self.assertRaisesRegex(RuntimeError, reason):
                    self.run_replay([event])
                self.assertTrue(self.connection.closed)

    def test_timeout_cancels_pending_receiver_and_preserves_artifacts(self):
        connection = FakeConnection([])

        async def never_respond():
            await asyncio.Future()

        connection.recv = never_respond
        with mock.patch.dict(sys.modules, {
            "websockets": SimpleNamespace(connect=lambda *_args, **_kwargs: connection)
        }):
            with self.assertRaisesRegex(RuntimeError, "exceeded"):
                client.replay_audio("http://localhost:9000", self.wav, 0.01,
                                    time.perf_counter_ns(), self.prefix)
        self.assertTrue(connection.closed)
        self.assertTrue(Path(str(self.prefix) + ".json").exists())

    def test_artifact_error_does_not_mask_protocol_failure(self):
        with (mock.patch.object(client, "_save_artifacts", side_effect=OSError("disk full")),
              self.assertLogs(level="ERROR")):
            with self.assertRaisesRegex(RuntimeError, "server error"):
                self.run_replay([{"type": "error", "error": {"message": "original"}}])

    def test_does_not_accept_success_before_session_end(self):
        connection = FakeConnection(complete_response())
        original_send = connection.send

        async def send_without_session_end(message):
            if json.loads(message)["type"] != "session.close":
                await original_send(message)

        connection.send = send_without_session_end
        original_sleep = asyncio.sleep

        async def yield_without_delay(_delay):
            await original_sleep(0)

        with (mock.patch.dict(sys.modules, {
            "websockets": SimpleNamespace(connect=lambda *_args, **_kwargs: connection)
        }), mock.patch.object(client.asyncio, "sleep", yield_without_delay)):
            with self.assertRaisesRegex(RuntimeError, "exceeded"):
                client.replay_audio("http://localhost:9000", self.wav, 0.02,
                                    time.perf_counter_ns(), self.prefix)
        self.assertTrue(connection.closed)

    def test_rejects_wrong_audio_format_before_connecting(self):
        with wave.open(str(self.wav), "wb") as output:
            output.setnchannels(1)
            output.setsampwidth(2)
            output.setframerate(16000)
            output.writeframes(b"\x01\x00")
        with self.assertRaisesRegex(ValueError, "24 kHz mono PCM16"):
            client.replay_audio("http://localhost:9000", self.wav, 1,
                                time.perf_counter_ns(), self.prefix)


if __name__ == "__main__":
    unittest.main()
