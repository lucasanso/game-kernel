#!/usr/bin/env python3
"""Fake gk-scanworker used to test fault isolation. Behaviour comes from its own file name:
crash_worker.py exits abruptly on every analysis; hang_worker.py never answers. Never analyses anything."""

import json
import os
import struct
import sys
import time


def send(msg):
    body = json.dumps(msg).encode()
    sys.stdout.buffer.write(struct.pack("<I", len(body)) + body)
    sys.stdout.buffer.flush()


def main():
    mode = os.path.basename(sys.argv[0]).split("_")[0]
    send({"v": 1, "type": "hello", "component": "gk-scanworker", "version": "test", "protocol": 1,
          "methods": ["analyze"], "pid": os.getpid(), "rules": {"detection": 1, "indicators": 1, "errors": []}})
    while True:
        header = sys.stdin.buffer.read(4)
        if len(header) < 4:
            return
        body = sys.stdin.buffer.read(struct.unpack("<I", header)[0])
        msg = json.loads(body)
        if msg.get("method") != "analyze":
            continue
        if mode == "crash":
            os._exit(139)
        while True:  # hang
            time.sleep(1)


if __name__ == "__main__":
    main()
