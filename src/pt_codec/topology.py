"""
High-level editor for a Packet Tracer topology, on top of the .pkt codec.

Wraps the decoded XML tree with friendly methods. Keeps an in-memory state
that can be saved back to a .pkt at any time.
"""
from __future__ import annotations

import copy
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from lxml import etree

from .codec import decode_pkt, encode_pkt


# Default cable sub-types per cable type.
# eCopper auto-MDIX is normal on modern devices but we still pick canonical defaults.
_CABLE_DEFAULTS = {
    "eCopper": "eStraightThrough",
    "eCopperCrossOver": "eCrossOver",
    "eFiber": "eFiber",
    "eConsole": "eConsole",
    "eSerial": "eSerialDCE",
    "eCoaxial": "eCoaxial",
}


@dataclass
class DeviceInfo:
    name: str
    type: str               # "Router", "Switch", "PC", ...
    model: str              # "ISR4331", "2960-24TT", ...
    save_ref_id: str | None
    logical_x: float | None
    logical_y: float | None


@dataclass
class LinkInfo:
    from_ref: str
    from_port: str
    to_ref: str
    to_port: str
    cable_type: str         # "eCopper", "eFiber", ...
    sub_type: str | None    # "eCrossOver", "eStraightThrough", ...


class Topology:
    """In-memory wrapper around a decoded .pkt XML tree."""

    def __init__(self, xml_bytes: bytes):
        self._root = etree.fromstring(xml_bytes)

    # ------------------------------------------------------------------ I/O
    @classmethod
    def open(cls, pkt_path: str | Path) -> "Topology":
        blob = Path(pkt_path).read_bytes()
        xml = decode_pkt(blob)
        return cls(xml)

    def save(self, pkt_path: str | Path) -> None:
        xml = etree.tostring(self._root, xml_declaration=False, encoding="utf-8")
        Path(pkt_path).write_bytes(encode_pkt(xml))

    def to_xml(self) -> bytes:
        return etree.tostring(self._root, pretty_print=True, encoding="utf-8")

    # -------------------------------------------------------------- helpers
    def _devices_element(self):
        return self._root.find("NETWORK").find("DEVICES")

    def _links_element(self):
        return self._root.find("NETWORK").find("LINKS")

    def _find_device(self, name: str):
        for d in self._devices_element():
            engine = d.find("ENGINE")
            if engine is None:
                continue
            name_el = engine.find("NAME")
            if name_el is not None and (name_el.text or "").strip() == name:
                return d
        raise KeyError(f"device not found: {name!r}")

    @staticmethod
    def _device_info(d) -> DeviceInfo:
        engine = d.find("ENGINE")
        type_el = engine.find("TYPE")
        name_el = engine.find("NAME")
        ref_el = engine.find("SAVE_REF_ID")
        wsp = d.find("WORKSPACE")
        lx = ly = None
        if wsp is not None:
            logical = wsp.find("LOGICAL")
            if logical is not None:
                x = logical.findtext("X")
                y = logical.findtext("Y")
                lx = float(x) if x else None
                ly = float(y) if y else None
        return DeviceInfo(
            name=(name_el.text or "").strip() if name_el is not None else "",
            type=(type_el.text or "").strip() if type_el is not None else "",
            model=type_el.get("model", "") if type_el is not None else "",
            save_ref_id=(ref_el.text or "").strip() if ref_el is not None else None,
            logical_x=lx,
            logical_y=ly,
        )

    # ------------------------------------------------------------- queries
    def list_devices(self) -> list[DeviceInfo]:
        return [self._device_info(d) for d in self._devices_element()]

    def list_links(self) -> list[LinkInfo]:
        links_el = self._links_element()
        out: list[LinkInfo] = []
        if links_el is None:
            return out
        for link in links_el:
            cable = link.find("CABLE")
            if cable is None:
                continue
            # CABLE has FROM, PORT, TO, PORT (two PORT siblings) — order matters
            from_ref = (cable.findtext("FROM") or "").strip()
            to_ref = (cable.findtext("TO") or "").strip()
            ports = cable.findall("PORT")
            from_port = (ports[0].text or "").strip() if len(ports) >= 1 else ""
            to_port = (ports[1].text or "").strip() if len(ports) >= 2 else ""
            cable_type = (link.findtext("TYPE") or "").strip()
            sub_type = (cable.findtext("TYPE") or "").strip() or None
            out.append(LinkInfo(from_ref, from_port, to_ref, to_port, cable_type, sub_type))
        return out

    def get_version(self) -> str:
        v = self._root.findtext("VERSION")
        return (v or "").strip()

    # ----------------------------------------------------- running-config
    def get_running_config(self, device_name: str) -> str:
        d = self._find_device(device_name)
        rc = d.find("ENGINE").find("RUNNINGCONFIG")
        if rc is None:
            return ""
        return "\n".join((line.text or "") for line in rc.findall("LINE"))

    def set_running_config(self, device_name: str, config_text: str) -> int:
        """Replace the entire RUNNINGCONFIG with these lines. Returns line count."""
        d = self._find_device(device_name)
        engine = d.find("ENGINE")
        rc = engine.find("RUNNINGCONFIG")
        if rc is None:
            rc = etree.SubElement(engine, "RUNNINGCONFIG")
        for child in list(rc):
            rc.remove(child)
        lines = config_text.splitlines()
        for line in lines:
            el = etree.SubElement(rc, "LINE")
            el.text = line
        return len(lines)

    def append_to_config(self, device_name: str, lines: Iterable[str]) -> int:
        d = self._find_device(device_name)
        engine = d.find("ENGINE")
        rc = engine.find("RUNNINGCONFIG")
        if rc is None:
            rc = etree.SubElement(engine, "RUNNINGCONFIG")
        n = 0
        for line in lines:
            el = etree.SubElement(rc, "LINE")
            el.text = line
            n += 1
        return n

    # ----------------------------------------------------- save-ref-id mgmt
    def _existing_ref_ids(self) -> set[str]:
        out: set[str] = set()
        for el in self._root.iter("SAVE_REF_ID"):
            if el.text:
                out.add(el.text.strip())
        return out

    def _new_save_ref_id(self) -> str:
        existing = self._existing_ref_ids()
        while True:
            n = random.randint(10**18, 10**19 - 1)
            ref = f"save-ref-id:{n}"
            if ref not in existing:
                return ref

    # --------------------------------------------------------- library scan
    @classmethod
    def scan_library(cls, pkt_path: str | Path, out_dir: str | Path) -> dict[str, str]:
        """Extract each unique device from a .pkt into individual XML blueprints.

        Files are written as `<out_dir>/<MODEL>.xml`. Returns dict {model: filepath}.
        Devices with the same model are deduplicated (first one wins).
        """
        out_dir = Path(out_dir)
        out_dir.mkdir(parents=True, exist_ok=True)
        topo = cls.open(pkt_path)
        seen: dict[str, str] = {}
        for d in topo._devices_element():
            engine = d.find("ENGINE")
            if engine is None:
                continue
            type_el = engine.find("TYPE")
            if type_el is None:
                continue
            model = type_el.get("model", "").strip()
            if not model:
                model = (type_el.text or "").strip()
            if not model or model == "Power Distribution Device":
                # PT auto-adds Power Distribution Device; useless as a blueprint
                continue
            if model in seen:
                continue
            # Sanitize model for filename
            safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in model)
            target = out_dir / f"{safe}.xml"
            target.write_bytes(etree.tostring(d, pretty_print=True, encoding="utf-8"))
            seen[model] = str(target)
        return seen

    # ----------------------------------------------- add from model library
    def add_device_by_model(self, library_dir: str | Path,
                            model: str, new_name: str,
                            x: float = 200.0, y: float = 200.0) -> None:
        """Add a device by model name from the pre-scanned library.

        `library_dir`: path to the directory created by scan_library().
        `model`: exact model string (e.g. "ISR4331", "2960-24TT", "PC-PT").
        """
        # Check new_name unique
        try:
            self._find_device(new_name)
            raise ValueError(f"device named {new_name!r} already exists")
        except KeyError:
            pass

        library_dir = Path(library_dir)
        safe = "".join(c if c.isalnum() or c in "-_." else "_" for c in model)
        blueprint = library_dir / f"{safe}.xml"
        if not blueprint.exists():
            # Helpful error: list what's available
            available = sorted(p.stem for p in library_dir.glob("*.xml"))
            raise FileNotFoundError(
                f"no blueprint for model {model!r} in {library_dir}. "
                f"Available: {', '.join(available)}"
            )

        clone = etree.fromstring(blueprint.read_bytes())
        engine = clone.find("ENGINE")

        # Reassign SAVE_REF_ID
        new_ref = self._new_save_ref_id()
        ref_el = engine.find("SAVE_REF_ID")
        if ref_el is None:
            ref_el = etree.SubElement(engine, "SAVE_REF_ID")
        ref_el.text = new_ref

        # NAME / SYS_NAME
        name_el = engine.find("NAME")
        if name_el is None:
            name_el = etree.SubElement(engine, "NAME")
        name_el.text = new_name
        sys_el = engine.find("SYS_NAME")
        if sys_el is not None:
            sys_el.text = new_name

        # hostname in running-config (if any)
        rc = engine.find("RUNNINGCONFIG")
        if rc is not None:
            updated = False
            for line in rc.findall("LINE"):
                if line.text and line.text.startswith("hostname "):
                    line.text = f"hostname {new_name}"
                    updated = True
                    break
            if not updated:
                h = etree.Element("LINE")
                h.text = f"hostname {new_name}"
                rc.insert(0, h)

        # Position
        wsp = clone.find("WORKSPACE")
        if wsp is not None:
            logical = wsp.find("LOGICAL")
            if logical is not None:
                for tag, val in (("X", int(x)), ("Y", int(y))):
                    el = logical.find(tag)
                    if el is None:
                        el = etree.SubElement(logical, tag)
                    el.text = str(val)
        coord = engine.find("COORD_SETTINGS")
        if coord is not None:
            for tag, val in (("X_COORD", x), ("Y_COORD", y)):
                el = coord.find(tag)
                if el is None:
                    el = etree.SubElement(coord, tag)
                el.text = f"{float(val):.2f}"

        self._devices_element().append(clone)

    # ----------------------------------------------------- add from template
    def add_device_from_template(self, template_path: str | Path,
                                 source_name: str, new_name: str,
                                 x: float = 200.0, y: float = 200.0) -> None:
        """Clone a device by name from a template .pkt into this topology.

        - `source_name` is the device name in the template (e.g. "Router0").
        - `new_name` is the unique name to assign in this topology.
        - `(x, y)` are the logical workspace coordinates for the new device.
        """
        # Check new_name is unique here
        try:
            self._find_device(new_name)
            raise ValueError(f"device named {new_name!r} already exists")
        except KeyError:
            pass

        # Load template, find source device
        template = Topology.open(template_path)
        src = template._find_device(source_name)

        # Deep-copy the DEVICE element
        clone = copy.deepcopy(src)
        engine = clone.find("ENGINE")

        # Reassign SAVE_REF_ID (unique within this topology)
        new_ref = self._new_save_ref_id()
        ref_el = engine.find("SAVE_REF_ID")
        if ref_el is None:
            ref_el = etree.SubElement(engine, "SAVE_REF_ID")
        ref_el.text = new_ref

        # Set NAME / SYS_NAME
        name_el = engine.find("NAME")
        if name_el is None:
            name_el = etree.SubElement(engine, "NAME")
        name_el.text = new_name
        sys_el = engine.find("SYS_NAME")
        if sys_el is not None:
            sys_el.text = new_name

        # Update hostname in running-config (if present)
        rc = engine.find("RUNNINGCONFIG")
        if rc is not None:
            found_hostname = False
            for line in rc.findall("LINE"):
                if line.text and line.text.startswith("hostname "):
                    line.text = f"hostname {new_name}"
                    found_hostname = True
                    break
            if not found_hostname:
                # Insert a hostname line near the top
                h = etree.Element("LINE")
                h.text = f"hostname {new_name}"
                rc.insert(0, h)

        # Set position: WORKSPACE/LOGICAL X,Y
        wsp = clone.find("WORKSPACE")
        if wsp is not None:
            logical = wsp.find("LOGICAL")
            if logical is not None:
                xel = logical.find("X")
                yel = logical.find("Y")
                if xel is None:
                    xel = etree.SubElement(logical, "X")
                if yel is None:
                    yel = etree.SubElement(logical, "Y")
                xel.text = str(int(x))
                yel.text = str(int(y))

        # COORD_SETTINGS (physical world coords; we copy x,y too)
        coord = engine.find("COORD_SETTINGS")
        if coord is not None:
            for tag, val in (("X_COORD", x), ("Y_COORD", y)):
                el = coord.find(tag)
                if el is None:
                    el = etree.SubElement(coord, tag)
                el.text = f"{float(val):.2f}"

        # Append to DEVICES
        self._devices_element().append(clone)

    # ----------------------------------------------------------- add link
    def add_link(self, from_name: str, from_port: str,
                 to_name: str, to_port: str,
                 cable_type: str = "eCopper",
                 sub_type: str | None = None) -> None:
        """Create a link between two device ports.

        `cable_type` is one of: eCopper, eCopperCrossOver, eFiber, eConsole,
        eSerial, eCoaxial.
        """
        a = self._find_device(from_name)
        b = self._find_device(to_name)
        a_ref = a.find("ENGINE").findtext("SAVE_REF_ID", "").strip()
        b_ref = b.find("ENGINE").findtext("SAVE_REF_ID", "").strip()
        if not a_ref or not b_ref:
            raise ValueError("one of the devices has no SAVE_REF_ID; broken topology?")

        sub = sub_type or _CABLE_DEFAULTS.get(cable_type, "eStraightThrough")

        link = etree.Element("LINK")
        etree.SubElement(link, "TYPE").text = cable_type
        cable = etree.SubElement(link, "CABLE")
        etree.SubElement(cable, "LENGTH").text = "1"
        etree.SubElement(cable, "FUNCTIONAL").text = "true"
        etree.SubElement(cable, "FROM").text = a_ref
        etree.SubElement(cable, "PORT").text = from_port
        etree.SubElement(cable, "TO").text = b_ref
        etree.SubElement(cable, "PORT").text = to_port
        # Memory-address fields: PT regenerates these at runtime, so we set
        # plausible decimal placeholders.
        for tag in ("FROM_DEVICE_MEM_ADDR", "TO_DEVICE_MEM_ADDR",
                    "FROM_PORT_MEM_ADDR", "TO_PORT_MEM_ADDR"):
            etree.SubElement(cable, tag).text = str(random.randint(10**12, 10**13 - 1))
        etree.SubElement(cable, "GEO_VIEW_COLOR").text = "#f7990d"
        etree.SubElement(cable, "IS_MANAGED_IN_RACK_VIEW").text = "false"
        etree.SubElement(cable, "TYPE").text = sub

        links_el = self._links_element()
        if links_el is None:
            # NETWORK should always have a LINKS child; create if missing
            net = self._root.find("NETWORK")
            links_el = etree.SubElement(net, "LINKS")
        links_el.append(link)

    # -------------------------------------------------- end-device IP config
    # Wired port types we treat as "the primary NIC" on an end device.
    _WIRED_PORT_TYPES = (
        "eCopperFastEthernet",
        "eCopperGigabitEthernet",
        "eCopperEthernet",
    )

    def _find_primary_wired_port(self, device_el):
        """Return the first <PORT> element whose <TYPE> is a wired Ethernet variant."""
        for port in device_el.iter("PORT"):
            type_el = port.find("TYPE")
            if type_el is not None and (type_el.text or "").strip() in self._WIRED_PORT_TYPES:
                return port
        return None

    @staticmethod
    def _set_or_create(parent, tag: str, text: str | None) -> None:
        el = parent.find(tag)
        if el is None:
            el = etree.SubElement(parent, tag)
        el.text = text

    def get_pc_network(self, device_name: str) -> dict[str, str]:
        """Return the static IP config of an end device (PC, Laptop, Server, …).

        Returns a dict with keys: ip, mask, gateway, dns, dhcp (true/false).
        Empty string means unset.
        """
        d = self._find_device(device_name)
        engine = d.find("ENGINE")
        port = self._find_primary_wired_port(d)
        if port is None:
            raise ValueError(f"{device_name!r} has no wired Ethernet port")
        out = {
            "ip": (port.findtext("IP") or "").strip(),
            "mask": (port.findtext("SUBNET") or "").strip(),
            "gateway": (engine.findtext("GATEWAY") or "").strip(),
            "dns": "",
            "dhcp": (port.findtext("PORT_DHCP_ENABLE") or "false").strip(),
        }
        dns_client = engine.find("DNS_CLIENT")
        if dns_client is not None:
            out["dns"] = (dns_client.findtext("SERVER_IP") or "").strip()
        return out

    def set_pc_network(self, device_name: str,
                       ip: str | None = None,
                       mask: str | None = None,
                       gateway: str | None = None,
                       dns: str | None = None,
                       dhcp: bool | None = None) -> dict[str, str]:
        """Set the static IP / DHCP config of an end device (PC, Laptop, Server).

        Pass `dhcp=True` to clear the static config and enable DHCP, or pass
        `ip` + `mask` (+ optional `gateway`, `dns`) for a static config.
        Any field left as None is preserved.
        Returns the resulting config (same shape as get_pc_network).
        """
        d = self._find_device(device_name)
        engine = d.find("ENGINE")
        port = self._find_primary_wired_port(d)
        if port is None:
            raise ValueError(f"{device_name!r} has no wired Ethernet port")

        if dhcp is True:
            # Clear statics, enable DHCP
            self._set_or_create(port, "IP", "")
            self._set_or_create(port, "SUBNET", "")
            self._set_or_create(port, "PORT_GATEWAY", "")
            self._set_or_create(port, "PORT_DNS", "")
            self._set_or_create(port, "PORT_DHCP_ENABLE", "true")
        else:
            if dhcp is False or ip is not None or mask is not None:
                self._set_or_create(port, "PORT_DHCP_ENABLE", "false")
            if ip is not None:
                self._set_or_create(port, "IP", ip)
            if mask is not None:
                self._set_or_create(port, "SUBNET", mask)
            if gateway is not None:
                self._set_or_create(port, "PORT_GATEWAY", gateway)
                # Also set device-level GATEWAY (what PT's "IP Configuration" UI writes)
                self._set_or_create(engine, "GATEWAY", gateway)
            if dns is not None:
                self._set_or_create(port, "PORT_DNS", dns)
                # Device-level DNS_CLIENT/SERVER_IP
                dns_client = engine.find("DNS_CLIENT")
                if dns_client is None:
                    dns_client = etree.SubElement(engine, "DNS_CLIENT")
                self._set_or_create(dns_client, "SERVER_IP", dns)

        return self.get_pc_network(device_name)

    # -------------------------------------------------- remove device / link
    def remove_device(self, name: str) -> int:
        """Remove a device and all links referencing it. Returns count of removed links."""
        d = self._find_device(name)
        ref = d.find("ENGINE").findtext("SAVE_REF_ID", "").strip()
        # Remove the device
        self._devices_element().remove(d)
        # Remove any link referencing this device
        removed_links = 0
        links_el = self._links_element()
        if links_el is not None and ref:
            for link in list(links_el):
                cable = link.find("CABLE")
                if cable is None:
                    continue
                if (cable.findtext("FROM", "").strip() == ref or
                        cable.findtext("TO", "").strip() == ref):
                    links_el.remove(link)
                    removed_links += 1
        return removed_links

    def remove_link(self, from_name: str, from_port: str,
                    to_name: str, to_port: str) -> bool:
        """Remove the link matching the four parameters (order-insensitive). Returns True if removed."""
        a = self._find_device(from_name)
        b = self._find_device(to_name)
        a_ref = a.find("ENGINE").findtext("SAVE_REF_ID", "").strip()
        b_ref = b.find("ENGINE").findtext("SAVE_REF_ID", "").strip()
        links_el = self._links_element()
        if links_el is None:
            return False
        for link in list(links_el):
            cable = link.find("CABLE")
            if cable is None:
                continue
            f = cable.findtext("FROM", "").strip()
            t = cable.findtext("TO", "").strip()
            ports = cable.findall("PORT")
            if len(ports) < 2:
                continue
            fp = (ports[0].text or "").strip()
            tp = (ports[1].text or "").strip()
            if ((f == a_ref and t == b_ref and fp == from_port and tp == to_port) or
                (f == b_ref and t == a_ref and fp == to_port and tp == from_port)):
                links_el.remove(link)
                return True
        return False

    # ------------------------------------------------------- rename device
    def rename_device(self, old: str, new: str) -> None:
        d = self._find_device(old)
        engine = d.find("ENGINE")
        # NAME element
        name_el = engine.find("NAME")
        if name_el is not None:
            name_el.text = new
        # SYS_NAME element
        sys_el = engine.find("SYS_NAME")
        if sys_el is not None:
            sys_el.text = new
        # hostname line in running-config
        rc = engine.find("RUNNINGCONFIG")
        if rc is not None:
            for line in rc.findall("LINE"):
                if line.text and line.text.startswith("hostname "):
                    line.text = f"hostname {new}"
                    break
