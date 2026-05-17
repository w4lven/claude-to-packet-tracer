"""Inspect an existing .pkt file: print version, devices, links, and one config."""
from __future__ import annotations
import sys
from pathlib import Path

from pt_codec import Topology


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: python 01_inspect.py path/to/file.pkt")
        return 2

    t = Topology.open(sys.argv[1])
    print(f"PT version: {t.get_version()}")
    print(f"\nDevices ({len(t.list_devices())}):")
    for d in t.list_devices():
        print(f"  {d.name:25s}  {d.type:25s}  {d.model}")

    print(f"\nLinks ({len(t.list_links())}):")
    for l in t.list_links():
        print(f"  {l.from_port} <--{l.cable_type}--> {l.to_port}")

    devices = t.list_devices()
    if devices:
        first_router = next((d for d in devices if d.type == "Router"), None)
        if first_router:
            print(f"\nRunning-config of {first_router.name!r} (first 15 lines):")
            cfg = t.get_running_config(first_router.name)
            for line in cfg.splitlines()[:15]:
                print(f"  {line}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
