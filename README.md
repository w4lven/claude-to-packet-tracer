# claude-to-packet-tracer

> An MCP (Model Context Protocol) server that lets **Claude read, edit, and
> create Cisco Packet Tracer topologies** directly — in natural language.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Packet Tracer](https://img.shields.io/badge/Packet%20Tracer-8.2.1-orange)
![Status](https://img.shields.io/badge/status-beta-yellow)

You say:

> *"Open `lab.pkt`, replace Router0 with two ISR4331 routers connected by
> Gi0/0/0, add OSPF area 0 on both, save as `ospf_lab.pkt`."*

Claude calls the right tools, edits the underlying `.pkt`, saves it back.
You hit **File → Open Recent** in Packet Tracer and see the result.

---

## How it works

`.pkt` and `.pka` files are XML compressed with zlib and encrypted with
**Twofish-EAX** plus two custom XOR obfuscation passes. This project
includes a **pure-Python** codec that decodes/encodes the format — port
of the public [pka2xml](https://github.com/mircodz/pka2xml) algorithm.

On top of the codec sits a `Topology` editor and an **MCP server** that
exposes the editor as tools Claude can call.

```
.pkt file
   ↓ decode (Twofish-EAX + obfuscation + zlib)
XML topology
   ↓ Topology (lxml)
Edits (running-configs, devices, links, …)
   ↑ encode
.pkt file (ready to open in PT)
```

Tested on **Packet Tracer 8.2.1.0118** (Windows) with Python 3.10+.

---

## Quickstart

### 1. Install

```powershell
git clone https://github.com/w4lven/claude-to-packet-tracer.git
cd claude-to-packet-tracer
python -m pip install -e .
```

### 2. Wire it into Claude Code

```powershell
claude mcp add --scope user packet-tracer "C:\path\to\claude-to-packet-tracer\run_mcp.bat"
```

Verify with:

```powershell
claude mcp list
# packet-tracer: ... - ✓ Connected
```

Restart Claude Code (or VSCode if you use the extension). Type `/mcp`
and the `packet-tracer` server should be listed.

### 3. Try it

In Claude Code, ask:

> *"Open `C:\Users\me\Desktop\test.pkt`, list its devices, and show me
> the running-config of the first router."*

Claude will call `pkt_open`, `pkt_list_devices`, `pkt_get_config`.

---

## Available MCP tools

| Tool | Purpose |
|---|---|
| `pkt_open(path)` | Load a `.pkt` into memory |
| `pkt_list_devices()` | List devices (name, type, model, position) |
| `pkt_list_links()` | List links between device ports |
| `pkt_get_config(device)` | Get IOS running-config of a device |
| `pkt_set_config(device, text)` | Replace the running-config |
| `pkt_append_config(device, lines)` | Append lines to the running-config |
| `pkt_rename_device(old, new)` | Rename (NAME + SYS_NAME + hostname) |
| `pkt_add_device(template, source, new, x, y)` | Clone a device from any template `.pkt` |
| `pkt_add_device_by_model(library_dir, model, new, x, y)` | Pick a device by model name from a scanned library |
| `pkt_scan_library(pkt, out_dir)` | Extract per-model XML blueprints from a master `.pkt` |
| `pkt_add_link(a, port_a, b, port_b, cable_type)` | Connect two ports (eCopper / eFiber / eSerial / …) |
| `pkt_remove_device(name)` | Remove a device and all its links |
| `pkt_remove_link(a, port_a, b, port_b)` | Remove one specific link |
| `pkt_new_from_template(template)` | Start a new in-memory topology |
| `pkt_save(path?)` | Save back to `.pkt` |
| `pkt_dump_xml(path)` | Debug: dump the raw decoded XML |

## Device library

The project ships with a pre-scanned library under
[`samples/library/`](samples/library/) covering **38 Cisco models**:

- **Routers**: ISR4331, ISR4321, 1841, 1941, 2620XM, 2621XM, 2811,
  2901, 2911, 819HG-4G-IOX, 819HGW, 829, CGR1240, Router-PT, Router-PT-Empty
- **Switches**: 2960-24TT, 2950-24, 2950T-24, 3560-24PS, 3650-24PS,
  IE-2000, Switch-PT, Switch-PT-Empty, Bridge-PT
- **End devices**: PC-PT, Laptop-PT, Server-PT, Printer-PT, TabletPC-PT,
  TV-PT, SMARTPHONE-PT, WiredEndDevice-PT, WirelessEndDevice-PT
- **Phones**: 7960 (IP), Home-VoIP-PT, Analog-Phone-PT
- **Misc**: NetworkController, Sniffer

To regenerate the library after a Packet Tracer update:

1. Create a fresh `.pkt` in the new PT version with one of every model you want.
2. Run:
   ```python
   from pt_codec import Topology
   Topology.scan_library("my_kitchen_sink.pkt", "samples/library")
   ```

## Workflow

Because Packet Tracer doesn't watch files for changes, the loop is:

1. Ask Claude to do something
2. Claude calls the MCP tools, edits the `.pkt`, saves it
3. In Packet Tracer: **File → Open Recent → \[top entry\]** (one click)
4. Packet Tracer reloads with your changes

---

## Examples

```python
# See examples/01_inspect.py
from pt_codec import Topology

t = Topology.open("lab.pkt")
for d in t.list_devices():
    print(d.name, d.model)
print(t.get_running_config("Router0"))
```

```python
# See examples/02_build_topology.py — build a CCNA topology from scratch
t = Topology.open("samples/biblio.pkt")
# (wipe devices/links here)
t.add_device_by_model("samples/library", "ISR4331", "R1", x=200, y=200)
t.add_device_by_model("samples/library", "ISR4331", "R2", x=500, y=200)
t.add_link("R1", "GigabitEthernet0/0/0", "R2", "GigabitEthernet0/0/0")
t.save("two_routers.pkt")
```

---

## Project layout

```
claude-to-packet-tracer/
├── src/
│   ├── pt_codec/           # .pkt codec + Topology editor
│   │   ├── codec.py        # Twofish-EAX + obfuscation + zlib
│   │   └── topology.py     # high-level editor (lxml)
│   └── pt_mcp_server/
│       └── server.py       # FastMCP server exposing the tools
├── samples/
│   └── library/            # 38 device blueprints (XML)
├── examples/               # Standalone Python demos
├── scripts/                # CLI helpers (decode_pkt, test_roundtrip, …)
├── tests/                  # pytest tests
└── run_mcp.bat             # Windows launcher used by `claude mcp add`
```

---

## Limits

- ✅ Routers / switches: full running-config R/W (CCNA-level IOS).
- ❌ End devices (PC, Laptop, Server): network settings (IP, DNS,
  gateway) live in a different XML branch and are **not yet** exposed
  via the MCP. PR welcome.
- ❌ Wireless devices (AP, WLC): same — not yet exposed.
- ❌ IoT devices: not yet exposed.

These could land in a v0.2.

---

## Disclaimer

This project is independent and **not affiliated with, endorsed by, or
sponsored by Cisco Systems**. "Cisco", "Packet Tracer", and related
marks belong to Cisco Systems, Inc.

The codec is a clean-room Python implementation of the publicly
documented [pka2xml](https://github.com/mircodz/pka2xml) algorithm.
It is intended for **legitimate interoperability** with `.pkt` /
`.pka` files you have created or legally received — for example, to
script edits to your own NetAcad labs.

You are responsible for complying with the Cisco Packet Tracer end-user
license agreement and your local laws.

---

## Credits

- The codec algorithm was reverse-engineered and documented by the
  authors of [pka2xml](https://github.com/mircodz/pka2xml) (Mirco
  Domeniconi et al.). This project ports their algorithm to pure Python.
- Built on the official [Model Context Protocol](https://modelcontextprotocol.io/)
  Python SDK.

---

## License

[MIT](LICENSE) © 2026 walven
