"""Verify decode -> encode -> decode produces identical XML."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))
from pt_codec import decode_pkt, encode_pkt

src = Path(sys.argv[1])
blob = src.read_bytes()
print(f"Source: {src.name} ({len(blob)} bytes)")

xml1 = decode_pkt(blob)
print(f"Decoded XML: {len(xml1)} bytes")

blob2 = encode_pkt(xml1)
print(f"Re-encoded: {len(blob2)} bytes")

xml2 = decode_pkt(blob2)
print(f"Re-decoded XML: {len(xml2)} bytes")

if xml1 == xml2:
    print("OK: XML round-trip identical")
else:
    print("FAIL: XML differs after round-trip")
    sys.exit(1)

# Write the re-encoded file so user can try opening it in PT
out = src.with_suffix(".rt.pkt")
out.write_bytes(blob2)
print(f"Wrote re-encoded file: {out}")
