"""Capture real test output and one local streaming benchmark."""

import hashlib
import json
import io
import platform
import queue
import sys
import tempfile
import time
import unittest
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

import cryptography
from securechat.crypto import Identity
from securechat.protocol import Peer


def wait(events, kind):
    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        event = events.get(timeout=max(0.01, deadline - time.monotonic()))
        if event["type"] == "error":
            raise RuntimeError(event["message"])
        if event["type"] == kind:
            return event
    raise TimeoutError(kind)


def main():
    output = ROOT / "output" / "evidence"
    output.mkdir(parents=True, exist_ok=True)
    captured = io.StringIO()
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    tests = unittest.TextTestRunner(stream=captured, verbosity=2).run(suite)
    (output / "tests-output.txt").write_text(captured.getvalue(), encoding="utf-8")
    if not tests.wasSuccessful():
        print(captured.getvalue())
        raise SystemExit(1)
    with tempfile.TemporaryDirectory() as temporary:
        folder = Path(temporary)
        aq, bq = queue.Queue(), queue.Queue()
        aid, bid = Identity.generate(), Identity.generate()
        a = Peer("Alice", aid, folder / "a", aq.put, lambda name, fp: name == "Bob" and fp == bid.fingerprint)
        b = Peer("Bob", bid, folder / "b", bq.put, lambda name, fp: name == "Alice" and fp == aid.fingerprint)
        try:
            started = time.perf_counter()
            a.connect("127.0.0.1", b.listen("127.0.0.1", 0))
            wait(aq, "connected")
            wait(bq, "connected")
            handshake_seconds = time.perf_counter() - started
            source = folder / "benchmark-8MiB.bin"
            with source.open("wb") as stream:
                block = bytes(range(256)) * 4096
                for _ in range(8):
                    stream.write(block)
            started = time.perf_counter()
            a.send_file(source)
            elapsed = time.perf_counter() - started
            received = wait(bq, "file_received")
            if Path(received["path"]).read_bytes() != source.read_bytes():
                raise AssertionError("Benchmark bytes differ")
            result = {"recorded_at": datetime.now().astimezone().isoformat(timespec="seconds"),
                      "python": platform.python_version(), "platform": platform.platform(),
                      "cryptography": cryptography.__version__, "tests_passed": tests.testsRun,
                      "handshake_seconds": handshake_seconds, "file_bytes": source.stat().st_size,
                      "file_seconds": elapsed, "throughput_MiB_s": 8 / elapsed,
                      "file_sm3": hashlib.new("sm3", source.read_bytes()).hexdigest(),
                      "byte_exact": True, "scope": "one local loopback run, not a LAN guarantee"}
            (output / "verification.json").write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
            print(json.dumps(result, ensure_ascii=False, indent=2))
        finally:
            a.close()
            b.close()
            a.wait_closed()
            b.wait_closed()


if __name__ == "__main__":
    main()
