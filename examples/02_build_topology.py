"""Build a small CCNA topology from scratch using the device library.

Result: 2 routers in a row + 1 switch + 2 PCs:

    PC1 --- SW1 --- R1 --- R2

Usage:
    python 02_build_topology.py path/to/library/  out.pkt
"""
from __future__ import annotations
import sys
from pathlib import Path

from pt_codec import Topology


def main() -> int:
    if len(sys.argv) < 3:
        print("usage: python 02_build_topology.py <library_dir> <out.pkt>")
        return 2

    library_dir = Path(sys.argv[1])
    out_path = Path(sys.argv[2])

    # Start by loading any .pkt to get a valid PT XML skeleton, then wipe the devices/links.
    # The library_dir's parent should contain a biblio.pkt produced by scan_library.
    skeleton = library_dir.parent / "biblio.pkt"
    if not skeleton.exists():
        print(f"ERROR: skeleton .pkt not found at {skeleton}")
        print("Create one in Packet Tracer (any saved file) and re-run.")
        return 1

    t = Topology.open(skeleton)
    t.clear()  # start from a blank workspace

    # Add devices
    t.add_device_by_model(library_dir, "ISR4331", "R1", x=200, y=200)
    t.add_device_by_model(library_dir, "ISR4331", "R2", x=500, y=200)
    t.add_device_by_model(library_dir, "2960-24TT", "SW1", x=200, y=400)
    t.add_device_by_model(library_dir, "PC-PT", "PC1", x=100, y=550)
    t.add_device_by_model(library_dir, "PC-PT", "PC2", x=300, y=550)

    # Link them
    t.add_link("R1", "GigabitEthernet0/0/0", "R2", "GigabitEthernet0/0/0")
    t.add_link("R1", "GigabitEthernet0/0/1", "SW1", "FastEthernet0/1")
    t.add_link("SW1", "FastEthernet0/2", "PC1", "FastEthernet0")
    t.add_link("SW1", "FastEthernet0/3", "PC2", "FastEthernet0")

    t.save(out_path)
    print(f"OK: built topology, saved to {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
