"""
MVP edit test: change Router0's hostname via the running-config, re-encode,
write a new .pkt. User opens it in PT and verifies the hostname changed.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent / "src"))
from pt_codec import decode_pkt, encode_pkt
from lxml import etree

NEW_HOSTNAME = "ClaudeRouter"

src = Path(sys.argv[1])
dst = src.with_name(src.stem + ".edited.pkt")

blob = src.read_bytes()
xml = decode_pkt(blob)
tree = etree.fromstring(xml)

# Find the first router and edit its running-config hostname
for device in tree.find("NETWORK").find("DEVICES"):
    engine = device.find("ENGINE")
    if engine is None:
        continue
    type_el = engine.find("TYPE")
    if type_el is None or type_el.text != "Router":
        continue

    name_el = engine.find("NAME")
    print(f"Editing device: {name_el.text}")

    rc = engine.find("RUNNINGCONFIG")
    if rc is None:
        print("  no RUNNINGCONFIG, skipping")
        continue

    changed = False
    for line in rc.findall("LINE"):
        if line.text and line.text.startswith("hostname "):
            print(f"  before: {line.text!r}")
            line.text = f"hostname {NEW_HOSTNAME}"
            print(f"  after:  {line.text!r}")
            changed = True
            break

    if not changed:
        print("  WARNING: no hostname line found")
    break

# Also update SYS_NAME for good measure (visible in PT's device list)
new_xml = etree.tostring(tree, xml_declaration=False, encoding="utf-8")
new_blob = encode_pkt(new_xml)
dst.write_bytes(new_blob)
print(f"\nWrote: {dst} ({len(new_blob)} bytes)")
print(f"-> Open this file in Packet Tracer. Router0 should now respond to "
      f"the hostname '{NEW_HOSTNAME}' in its CLI prompt.")
