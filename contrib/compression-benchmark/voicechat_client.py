#!/usr/bin/env python3
"""Replay one recorded conversation through the VoiceChat realtime API.

The generated speech is sampled by the server. Validation checks functional
output, not equality of generated audio or text across checkpoint/restore.
"""

import asyncio
import base64
import binascii
import hashlib
import json
import logging
from pathlib import Path
import time
from urllib.parse import urlsplit, urlunsplit
import uuid
import wave


SAMPLE_RATE = 24000
CHUNK_SECONDS = 0.08
TRAILING_SILENCE_SECONDS = 20
CHUNK_BYTES = int(SAMPLE_RATE * CHUNK_SECONDS) * 2


def _websocket_url(base_url):
    parsed = urlsplit(base_url)
    schemes = {"http": "ws", "https": "wss", "ws": "ws", "wss": "wss"}
    if parsed.scheme not in schemes or not parsed.netloc:
        raise ValueError("VoiceChat URL must use http, https, ws or wss")
    if parsed.query or parsed.fragment or parsed.path not in ("", "/", "/v1/realtime"):
        raise ValueError("VoiceChat URL must name the server or /v1/realtime")
    return urlunsplit((schemes[parsed.scheme], parsed.netloc,
                       "/v1/realtime", "", ""))


def _read_audio(path):
    with wave.open(str(path), "rb") as source:
        if (source.getnchannels() != 1 or source.getsampwidth() != 2
                or source.getframerate() != SAMPLE_RATE
                or source.getcomptype() != "NONE"):
            raise ValueError("VoiceChat input must be 24 kHz mono PCM16 WAV")
        audio = source.readframes(source.getnframes())
        if len(audio) != source.getnframes() * 2:
            raise ValueError("VoiceChat input WAV is truncated")
    if not audio or not any(audio):
        raise ValueError("VoiceChat input WAV must contain non-silent audio")
    return audio


def _event(message):
    try:
        event = json.loads(message)
    except (ValueError, TypeError) as error:
        raise RuntimeError("VoiceChat sent an invalid JSON event") from error
    if not isinstance(event, dict) or not isinstance(event.get("type"), str):
        raise RuntimeError("VoiceChat event has no string type")
    if event["type"] == "error":
        raise RuntimeError(f"VoiceChat server error: {event.get('error')}")
    if event["type"] == "response.function_call_arguments.done":
        raise RuntimeError("VoiceChat requested a tool despite tools=[]")
    return event


async def _send_event(connection, event_type, **fields):
    await connection.send(json.dumps({
        "type": event_type, "event_id": str(uuid.uuid4()), **fields,
    }))


async def _replay(url, audio, state):
    # Keep the ordinary benchmark and its tests usable without websockets.
    try:
        import websockets
    except ImportError as error:
        raise RuntimeError("VoiceChat benchmark requires the websockets package") from error

    async with websockets.connect(url, max_size=4 * 1024 * 1024,
                                  close_timeout=5) as connection:
        for expected in ("session.created", "session.updated"):
            event = _event(await connection.recv())
            state["events"].append(event)
            if event["type"] != expected:
                raise RuntimeError(f"Expected VoiceChat {expected}, got {event['type']}")
            if expected == "session.created":
                await _send_event(connection, "session.update", session={
                    "audio": {
                        "input": {"format": {"type": "audio/pcm", "rate": SAMPLE_RATE}},
                        "output": {"format": {"type": "audio/pcm", "rate": SAMPLE_RATE}},
                    },
                    "tools": [],
                })

        async def receive():
            while True:
                event = _event(await connection.recv())
                kind = event["type"]
                if kind == "response.output_audio.delta":
                    try:
                        chunk = base64.b64decode(event.get("delta", ""), validate=True)
                    except (ValueError, TypeError, binascii.Error) as error:
                        raise RuntimeError("VoiceChat returned invalid PCM audio") from error
                    if len(chunk) % 2:
                        raise RuntimeError("VoiceChat returned an incomplete PCM16 sample")
                    if chunk:
                        if state["first_audio_packet_ns"] is None:
                            state["first_audio_packet_ns"] = time.monotonic_ns()
                        state["audio"].extend(chunk)
                    state["events"].append({
                        key: value for key, value in event.items() if key != "delta"
                    } | {"audio_bytes": len(chunk)})
                else:
                    state["events"].append(event)
                if kind == "response.output_audio_transcript.done":
                    transcript = event.get("transcript")
                    if not isinstance(transcript, str):
                        raise RuntimeError("VoiceChat agent transcript is not a string")
                    state["transcripts"].append(transcript)
                elif kind == "conversation.item.input_audio_transcription.completed":
                    transcript = event.get("transcript")
                    if not isinstance(transcript, str):
                        raise RuntimeError("VoiceChat user transcript is not a string")
                    state["user_transcripts"].append(transcript)
                elif kind == "response.created":
                    response_id = event.get("response", {}).get("id")
                    if not isinstance(response_id, str) or not response_id:
                        raise RuntimeError("VoiceChat response.created has no response ID")
                    state["active_responses"].add(response_id)
                elif kind == "response.done":
                    response = event.get("response", {})
                    if response.get("status") != "completed":
                        raise RuntimeError(f"VoiceChat response did not complete: {response}")
                    response_id = response.get("id")
                    if response_id not in state["active_responses"]:
                        raise RuntimeError("VoiceChat completed an unknown response")
                    state["active_responses"].remove(response_id)
                    state["completed_responses"] += 1
                elif kind == "session.end":
                    if not state["closing"]:
                        raise RuntimeError("VoiceChat session ended before audio replay finished")
                    if event.get("stats", {}).get("chunks_dropped", 0):
                        raise RuntimeError("VoiceChat dropped input audio chunks")
                    state["session_ended"] = True
                    state["session_complete_ns"] = time.monotonic_ns()
                    return

        async def send():
            padded = audio + bytes(SAMPLE_RATE * 2 * TRAILING_SILENCE_SECONDS)
            started = asyncio.get_running_loop().time()
            for index, offset in enumerate(range(0, len(padded), CHUNK_BYTES)):
                deadline = started + index * CHUNK_SECONDS
                await asyncio.sleep(max(0, deadline - asyncio.get_running_loop().time()))
                chunk = padded[offset:offset + CHUNK_BYTES]
                await _send_event(connection, "input_audio_buffer.append",
                                  audio=base64.b64encode(chunk).decode("ascii"))
            # Give the final frame its playback interval before closing.
            await asyncio.sleep(CHUNK_SECONDS)
            state["closing"] = True
            await _send_event(connection, "session.close")

        tasks = [asyncio.create_task(receive()), asyncio.create_task(send())]
        try:
            await asyncio.gather(*tasks)
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)


def _save_artifacts(output_prefix, result, state):
    prefix = Path(output_prefix)
    prefix.parent.mkdir(parents=True, exist_ok=True)
    result.update({
        "audio_path": str(prefix) + ".wav",
        "transcript_path": str(prefix) + ".transcript.json",
        "events_path": str(prefix) + ".events.json",
        "result_path": str(prefix) + ".json",
        "transcript": "\n".join(state["transcripts"]).strip(),
        "user_transcript": "\n".join(state["user_transcripts"]).strip(),
        "audio_sha256": hashlib.sha256(state["audio"]).hexdigest(),
        "response_completed": bool(state["completed_responses"])
        and not state["active_responses"],
    })
    result["transcript_sha256"] = hashlib.sha256(result["transcript"].encode()).hexdigest()
    with wave.open(result["audio_path"], "wb") as output:
        output.setnchannels(1)
        output.setsampwidth(2)
        output.setframerate(SAMPLE_RATE)
        output.writeframes(state["audio"])
    Path(result["transcript_path"]).write_text(json.dumps({
        "agent": result["transcript"], "user": result["user_transcript"],
    }, indent=2) + "\n")
    Path(result["events_path"]).write_text(json.dumps(state["events"], indent=2) + "\n")
    Path(result["result_path"]).write_text(json.dumps(result, indent=2) + "\n")


def replay_audio(base_url, wav_path, timeout, operation_started_ns, output_prefix):
    """Return functional validation and timings after the voice session closes.

    ``operation_started_ns`` uses ``time.monotonic_ns()``, like the common
    benchmark's cold-start and restore timers. Generated-output hashes are
    recorded for inspection, not used as a determinism assertion.
    """
    url = _websocket_url(base_url)
    audio = _read_audio(wav_path)
    if timeout <= 0:
        raise ValueError("VoiceChat timeout must be positive")
    started_ns = time.monotonic_ns()
    state = {"audio": bytearray(), "events": [], "transcripts": [],
             "user_transcripts": [], "active_responses": set(),
             "completed_responses": 0, "first_audio_packet_ns": None,
             "session_complete_ns": None, "session_ended": False, "closing": False}
    result = {"valid": False, "validation": "functional",
              "input_duration_s": len(audio) / (SAMPLE_RATE * 2),
              "input_sha256": hashlib.sha256(audio).hexdigest(),
              "trailing_silence_s": TRAILING_SILENCE_SECONDS}

    async def run():
        await asyncio.wait_for(_replay(url, audio, state), timeout=timeout)

    try:
        asyncio.run(run())
        if (not state["completed_responses"] or state["active_responses"]
                or not state["session_ended"]):
            raise RuntimeError("VoiceChat returned no complete response and closed session")
        if not "".join(state["transcripts"]).strip():
            raise RuntimeError("VoiceChat returned no agent transcript")
        if not "".join(state["user_transcripts"]).strip():
            raise RuntimeError("VoiceChat returned no user transcript")
        if not any(state["audio"]):
            raise RuntimeError("VoiceChat returned no non-silent audio")
        result["valid"] = True
    except TimeoutError as error:
        result["error"] = f"VoiceChat replay exceeded {timeout} seconds"
        raise RuntimeError(result["error"]) from error
    except Exception as error:
        result["error"] = str(error)
        raise
    finally:
        result["request_us"] = (time.monotonic_ns() - started_ns) // 1000
        for field, end_ns, start_ns in (
            ("request_to_first_audio_packet_us", state["first_audio_packet_ns"], started_ns),
            ("operation_to_first_audio_packet_us", state["first_audio_packet_ns"], operation_started_ns),
            ("operation_to_session_complete_us", state["session_complete_ns"],
             operation_started_ns),
        ):
            result[field] = None if end_ns is None else (end_ns - start_ns) // 1000
        try:
            _save_artifacts(output_prefix, result, state)
        except OSError:
            if "error" not in result:
                raise
            logging.exception("Could not save VoiceChat failure artifacts")
    return result
