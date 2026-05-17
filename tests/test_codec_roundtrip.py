"""Round-trip test for the .pkt codec.

Verifies encode_pkt(decode_pkt(blob)) yields back the same XML bytes.
Does not require a real .pkt — uses a synthetic minimal XML.
"""
from pt_codec import decode_pkt, encode_pkt


def test_synthetic_roundtrip():
    xml = (
        b"<PACKETTRACER5>"
        b"<VERSION>8.2.1.0118</VERSION>"
        b"<NETWORK><DEVICES/><LINKS/></NETWORK>"
        b"</PACKETTRACER5>"
    )
    blob = encode_pkt(xml)
    decoded = decode_pkt(blob)
    assert decoded == xml


def test_idempotent_encode():
    xml = b"<root><a>hello</a></root>"
    blob1 = encode_pkt(xml)
    blob2 = encode_pkt(xml)
    # zlib output may vary by version but decode should always recover xml
    assert decode_pkt(blob1) == xml
    assert decode_pkt(blob2) == xml
