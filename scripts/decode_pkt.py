"""
CLI: decode a .pkt file and dump its XML.

    python decode_pkt.py samples/test1.pkt           # prints XML to stdout
    python decode_pkt.py samples/test1.pkt out.xml   # writes to file
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))
from pt_codec import decode_pkt, PktDecodeError


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 2

    src = Path(sys.argv[1])
    if not src.exists():
        print(f"ERROR: not found: {src}")
        return 1

    try:
        xml = decode_pkt(src.read_bytes())
    except PktDecodeError as e:
        print(f"DECODE FAILED: {e}")
        print(f"File size: {src.stat().st_size} bytes")
        return 1

    print(f"OK: decoded {len(xml)} bytes of XML from {src.name}", file=sys.stderr)

    if len(sys.argv) >= 3:
        out = Path(sys.argv[2])
        out.write_bytes(xml)
        print(f"Wrote: {out}", file=sys.stderr)
    else:
        sys.stdout.buffer.write(xml[:4000])
        if len(xml) > 4000:
            sys.stderr.write(f"\n...[truncated, full size {len(xml)} bytes]\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
