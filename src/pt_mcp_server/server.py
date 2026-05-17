"""
MCP server for Cisco Packet Tracer .pkt files.

Exposes tools to open, inspect, and edit a .pkt topology, then save it back.
The server holds one in-memory topology at a time, identified by `path`.

Run:
    python -m pt_mcp_server.server
"""
from __future__ import annotations

import sys
from pathlib import Path

# Allow `python -m pt_mcp_server.server` from the project root.
ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))

from mcp.server.fastmcp import FastMCP

from pt_codec import Topology, PktDecodeError


mcp = FastMCP("packet-tracer")


# ---------------------------------------------------------------- state
class _State:
    topology: Topology | None = None
    path: str | None = None


_state = _State()


def _require() -> Topology:
    if _state.topology is None:
        raise RuntimeError(
            "no topology open; call pkt_open(path) first"
        )
    return _state.topology


# ---------------------------------------------------------------- tools
@mcp.tool()
def pkt_open(path: str) -> str:
    """Open a .pkt file and load its topology into memory.

    Returns a summary: version, device count, link count.
    """
    try:
        _state.topology = Topology.open(path)
    except PktDecodeError as e:
        return f"ERROR decoding .pkt: {e}"
    except FileNotFoundError:
        return f"ERROR: file not found: {path}"

    _state.path = path
    t = _state.topology
    return (
        f"Opened {path}\n"
        f"  PT version: {t.get_version()}\n"
        f"  Devices: {len(t.list_devices())}\n"
        f"  Links:   {len(t.list_links())}"
    )


@mcp.tool()
def pkt_list_devices() -> str:
    """List all devices in the currently-open topology.

    Returns one line per device: name, type, model, logical position.
    """
    t = _require()
    rows = []
    for d in t.list_devices():
        pos = f"({d.logical_x},{d.logical_y})" if d.logical_x is not None else "(-)"
        rows.append(f"{d.name}\ttype={d.type}\tmodel={d.model}\tpos={pos}")
    return "\n".join(rows) if rows else "(no devices)"


@mcp.tool()
def pkt_list_links() -> str:
    """List all links: from_device.from_port <-cable-> to_device.to_port.

    Note: device references are save-ref-ids; correlate with pkt_list_devices.
    """
    t = _require()
    # Build ref->name map
    name_by_ref = {}
    for d in t.list_devices():
        if d.save_ref_id:
            name_by_ref[d.save_ref_id] = d.name

    rows = []
    for l in t.list_links():
        a = name_by_ref.get(l.from_ref, l.from_ref)
        b = name_by_ref.get(l.to_ref, l.to_ref)
        rows.append(f"{a}.{l.from_port} <-{l.cable_type}/{l.sub_type}-> {b}.{l.to_port}")
    return "\n".join(rows) if rows else "(no links)"


@mcp.tool()
def pkt_get_config(device_name: str) -> str:
    """Get the running-config (IOS) of a device by name."""
    t = _require()
    try:
        return t.get_running_config(device_name)
    except KeyError as e:
        return f"ERROR: {e}"


@mcp.tool()
def pkt_set_config(device_name: str, config_text: str) -> str:
    """Replace the entire running-config of a device.

    `config_text` is the full IOS configuration, one command per line.
    Returns the number of lines written.
    """
    t = _require()
    try:
        n = t.set_running_config(device_name, config_text)
    except KeyError as e:
        return f"ERROR: {e}"
    return f"OK: wrote {n} lines to {device_name} running-config"


@mcp.tool()
def pkt_append_config(device_name: str, lines: str) -> str:
    """Append lines to a device's running-config. `lines` is a multi-line string."""
    t = _require()
    try:
        n = t.append_to_config(device_name, lines.splitlines())
    except KeyError as e:
        return f"ERROR: {e}"
    return f"OK: appended {n} lines to {device_name} running-config"


@mcp.tool()
def pkt_rename_device(old_name: str, new_name: str) -> str:
    """Rename a device. Updates NAME, SYS_NAME, and the hostname line in the running-config."""
    t = _require()
    try:
        t.rename_device(old_name, new_name)
    except KeyError as e:
        return f"ERROR: {e}"
    return f"OK: renamed {old_name} -> {new_name}"


@mcp.tool()
def pkt_scan_library(pkt_path: str, output_dir: str) -> str:
    """Scan a 'kitchen-sink' .pkt file and extract one XML blueprint per device model.

    Output files: <output_dir>/<MODEL>.xml (e.g. ISR4331.xml, 2960-24TT.xml).
    Run this once after creating a master .pkt that contains every model you
    want available, then use pkt_add_device_by_model with that library_dir.
    """
    try:
        result = Topology.scan_library(pkt_path, output_dir)
    except (PktDecodeError, FileNotFoundError) as e:
        return f"ERROR: {e}"
    return (
        f"OK: extracted {len(result)} blueprints to {output_dir}\n"
        + "\n".join(f"  {m}" for m in sorted(result))
    )


@mcp.tool()
def pkt_add_device_by_model(library_dir: str, model: str,
                            new_name: str,
                            x: float = 200.0, y: float = 200.0) -> str:
    """Add a device to the open topology by picking a model from the library.

    `library_dir`: dir produced by pkt_scan_library (e.g. ".../samples/library").
    `model`: exact model name (e.g. "ISR4331", "2960-24TT", "PC-PT", "Server-PT").
    `new_name`: unique name to assign in the topology.
    `(x, y)`: logical workspace coordinates.

    Default library on this machine: c:\\Users\\loanj\\Desktop\\MCP\\samples\\library
    Available models include: ISR4331, ISR4321, 1841, 1941, 2811, 2901, 2911,
    2620XM, 2621XM, 819HG-4G-IOX, 819HGW, 829, CGR1240, 2960-24TT, 2950-24,
    2950T-24, 3560-24PS, 3650-24PS, IE-2000, Router-PT, Switch-PT, Bridge-PT,
    PC-PT, Laptop-PT, Server-PT, Printer-PT, 7960 (IP phone),
    SMARTPHONE-PT, TabletPC-PT, TV-PT, Home-VoIP-PT, Analog-Phone-PT,
    NetworkController, Sniffer, WiredEndDevice-PT, WirelessEndDevice-PT.
    """
    t = _require()
    try:
        t.add_device_by_model(library_dir, model, new_name, x, y)
    except (KeyError, ValueError, FileNotFoundError) as e:
        return f"ERROR: {e}"
    return f"OK: added {model} as {new_name!r} at ({x},{y})"


@mcp.tool()
def pkt_add_device(template_path: str, source_name: str,
                   new_name: str, x: float = 200.0, y: float = 200.0) -> str:
    """Clone a device from a template .pkt file into the open topology.

    `template_path`: path to a .pkt containing a device to clone from.
    `source_name`: name of the device in the template (e.g. "Router0", "PC0", "Switch0").
    `new_name`: unique name to give the new device in the current topology.
    `(x, y)`: logical workspace coordinates.

    Tip: a default template lives at samples/template.pkt with Router0 (ISR4331),
    Switch0 (2960-24TT), PC0 (PC-PT).
    """
    t = _require()
    try:
        t.add_device_from_template(template_path, source_name, new_name, x, y)
    except (KeyError, ValueError) as e:
        return f"ERROR: {e}"
    except FileNotFoundError:
        return f"ERROR: template not found: {template_path}"
    return f"OK: cloned {source_name!r} from template -> {new_name!r} at ({x},{y})"


@mcp.tool()
def pkt_add_link(from_device: str, from_port: str,
                 to_device: str, to_port: str,
                 cable_type: str = "eCopper") -> str:
    """Create a link between two device ports.

    `cable_type`: eCopper (default), eCopperCrossOver, eFiber, eConsole, eSerial.
    Example: pkt_add_link("R1", "GigabitEthernet0/0/0", "PC1", "FastEthernet0").
    """
    t = _require()
    try:
        t.add_link(from_device, from_port, to_device, to_port, cable_type=cable_type)
    except (KeyError, ValueError) as e:
        return f"ERROR: {e}"
    return f"OK: linked {from_device}.{from_port} <-> {to_device}.{to_port} ({cable_type})"


@mcp.tool()
def pkt_remove_device(name: str) -> str:
    """Remove a device and all links referencing it."""
    t = _require()
    try:
        n = t.remove_device(name)
    except KeyError as e:
        return f"ERROR: {e}"
    return f"OK: removed device {name!r} and {n} link(s)"


@mcp.tool()
def pkt_remove_link(from_device: str, from_port: str,
                    to_device: str, to_port: str) -> str:
    """Remove the link between two specific ports (direction-insensitive)."""
    t = _require()
    try:
        removed = t.remove_link(from_device, from_port, to_device, to_port)
    except KeyError as e:
        return f"ERROR: {e}"
    return ("OK: link removed" if removed
            else "ERROR: no matching link found")


@mcp.tool()
def pkt_new_from_template(template_path: str) -> str:
    """Start a new in-memory topology by loading the template file.

    Useful when you want to build a topology from scratch. After this call,
    list_devices will show the devices present in the template; you can
    remove them or keep them as a base.
    """
    try:
        _state.topology = Topology.open(template_path)
    except (PktDecodeError, FileNotFoundError) as e:
        return f"ERROR: {e}"
    _state.path = None  # force user to choose a save path
    return f"OK: loaded template {template_path} as new working topology"


@mcp.tool()
def pkt_get_pc_network(device_name: str) -> str:
    """Get the IP/mask/gateway/DNS/DHCP settings of an end device (PC, Laptop, Server).

    Returns a multi-line summary. For routers/switches use pkt_get_config instead.
    """
    t = _require()
    try:
        cfg = t.get_pc_network(device_name)
    except (KeyError, ValueError) as e:
        return f"ERROR: {e}"
    return "\n".join(
        f"{k:8s}: {v if v else '(unset)'}" for k, v in cfg.items()
    )


@mcp.tool()
def pkt_set_pc_network(device_name: str,
                       ip: str | None = None,
                       mask: str | None = None,
                       gateway: str | None = None,
                       dns: str | None = None,
                       dhcp: bool | None = None) -> str:
    """Set the IP config of an end device (PC, Laptop, Server).

    Either pass `dhcp=True` to enable DHCP, or pass `ip` + `mask`
    (+ optional `gateway`, `dns`) for a static config.
    Any param left None is preserved.

    Example (static): pkt_set_pc_network("PC1", "192.168.1.10", "255.255.255.0",
                                          gateway="192.168.1.1", dns="8.8.8.8")
    Example (DHCP):   pkt_set_pc_network("PC1", dhcp=True)
    """
    t = _require()
    try:
        cfg = t.set_pc_network(device_name, ip=ip, mask=mask,
                               gateway=gateway, dns=dns, dhcp=dhcp)
    except (KeyError, ValueError) as e:
        return f"ERROR: {e}"
    return "OK\n" + "\n".join(
        f"  {k:8s}: {v if v else '(unset)'}" for k, v in cfg.items()
    )


@mcp.tool()
def pkt_get_ap_config(device_name: str) -> str:
    """Get the wireless config of an AP / wireless router.

    Returns SSID, authentication, encryption, channel, and broadcast state.
    """
    t = _require()
    try:
        cfg = t.get_ap_config(device_name)
    except (KeyError, ValueError) as e:
        return f"ERROR: {e}"
    return "\n".join(f"{k:15s}: {v if v else '(unset)'}" for k, v in cfg.items())


@mcp.tool()
def pkt_set_ap_config(device_name: str,
                     ssid: str | None = None,
                     authentication: str | None = None,
                     encryption: str | None = None,
                     password: str | None = None,
                     channel: int | None = None,
                     ssid_broadcast: bool | None = None) -> str:
    """Set the wireless config of an AP / wireless router.

    - authentication: open | wep | wpa-psk | wpa2-psk | wpa-enterprise | wpa2-enterprise
    - encryption:     none | wep40 | wep104 | aes | tkip | aes+tkip
    - password:       PSK / WEP key (only needed when authentication != open)
    - channel:        1-13 (2.4 GHz)

    Example: pkt_set_ap_config("AP1", ssid="MyLab", authentication="wpa2-psk",
                                encryption="aes", password="Cisco123!", channel=6)
    """
    t = _require()
    try:
        cfg = t.set_ap_config(device_name, ssid=ssid, authentication=authentication,
                              encryption=encryption, password=password,
                              channel=channel, ssid_broadcast=ssid_broadcast)
    except (KeyError, ValueError) as e:
        return f"ERROR: {e}"
    return "OK\n" + "\n".join(f"  {k:15s}: {v}" for k, v in cfg.items())


@mcp.tool()
def pkt_get_iot_registration(device_name: str) -> str:
    """Get the IoT registration config of a Smart Thing (Door, Light, Webcam, …).

    Shows registration mode (NO_SERVER / HOME_GATEWAY / REMOTE_SERVER),
    server address, username, password.
    """
    t = _require()
    try:
        cfg = t.get_iot_registration(device_name)
    except (KeyError, ValueError) as e:
        return f"ERROR: {e}"
    return "\n".join(f"{k:10s}: {v if v else '(unset)'}" for k, v in cfg.items())


@mcp.tool()
def pkt_set_iot_registration(device_name: str, mode: str,
                            server: str | None = None,
                            username: str | None = None,
                            password: str | None = None) -> str:
    """Configure how a Smart Thing registers to an IoT server.

    - mode: 'none', 'home_gateway' (local DLC100), or 'remote_server'
      (Registration Server).
    - server: server IP (only for home_gateway / remote_server)
    - username, password: credentials (only for remote_server)

    Example: pkt_set_iot_registration("SmartDoor1", "remote_server",
              server="192.168.1.10", username="admin", password="ciscoiot")
    """
    t = _require()
    try:
        cfg = t.set_iot_registration(device_name, mode=mode,
                                     server=server, username=username,
                                     password=password)
    except (KeyError, ValueError) as e:
        return f"ERROR: {e}"
    return "OK\n" + "\n".join(f"  {k:10s}: {v if v else '(unset)'}" for k, v in cfg.items())


@mcp.tool()
def pkt_list_mcu_projects(device_name: str) -> str:
    """List all programming projects on an MCU-PT or SBC-PT.

    Returns one line per project: name, language, files.
    """
    t = _require()
    try:
        projects = t.list_mcu_projects(device_name)
    except (KeyError, ValueError) as e:
        return f"ERROR: {e}"
    if not projects:
        return "(no projects)"
    return "\n".join(
        f"{p['project_name']:30s}  lang={p['language']:12s}  files={p['files']}"
        for p in projects
    )


@mcp.tool()
def pkt_get_mcu_script(device_name: str, project_name: str,
                       file_name: str | None = None) -> str:
    """Read the content of a script in an MCU/SBC project.

    If `file_name` is omitted, returns the first file (usually main.js/main.py).
    """
    t = _require()
    try:
        return t.get_mcu_script(device_name, project_name, file_name)
    except (KeyError, ValueError) as e:
        return f"ERROR: {e}"


@mcp.tool()
def pkt_set_mcu_script(device_name: str, project_name: str,
                       content: str,
                       language: str = "JavaScript",
                       file_name: str | None = None) -> str:
    """Create or update a script in an MCU/SBC project.

    - `language`: 'JavaScript' or 'Python' (used only when creating a project).
    - `file_name`: defaults to 'main.js' (JS) or 'main.py' (Python).

    If the project doesn't exist, it is created. If the file doesn't exist
    in the project, it is created.

    Example:
        pkt_set_mcu_script("MCU0", "Blink", '''
            function setup() { pinMode(1, OUTPUT); }
            function loop() { digitalWrite(1, HIGH); delay(500); digitalWrite(1, LOW); delay(500); }
        ''', language="JavaScript")
    """
    t = _require()
    try:
        t.set_mcu_script(device_name, project_name, content,
                         language=language, file_name=file_name)
    except (KeyError, ValueError) as e:
        return f"ERROR: {e}"
    return f"OK: wrote script to {device_name!r} / {project_name!r}"


@mcp.tool()
def pkt_save(path: str | None = None) -> str:
    """Save the current topology back to a .pkt file.

    If `path` is omitted, overwrites the originally-opened file.
    """
    t = _require()
    target = path or _state.path
    if target is None:
        return "ERROR: no path provided and no original path tracked"
    t.save(target)
    return f"OK: saved {target}"


@mcp.tool()
def pkt_dump_xml(path: str) -> str:
    """Debug helper: write the current topology's raw XML to a file."""
    t = _require()
    Path(path).write_bytes(t.to_xml())
    return f"OK: wrote XML to {path}"


def main() -> None:
    mcp.run()


if __name__ == "__main__":
    main()
