# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.4.1] - 2026-05-17

### Added

- `Topology.clear()` Python API and `pkt_clear_topology` MCP tool — remove
  all devices and links while keeping metadata. The previous workflow
  required reaching into private `_devices_element()` / `_links_element()`
  helpers; now it's a one-liner.
- `run_mcp.sh` launcher for Linux / macOS.
- README: explicit Compatibility section covering both PT versions and
  operating systems.

### Changed

- `_require()` error message now suggests both `pkt_open` and
  `pkt_new_from_template` so first-time users know how to start.
- Removed obsolete one-shot scripts (`scripts/test_edit.py`,
  `scripts/test_roundtrip.py`) — superseded by the proper test suite.
- Example `02_build_topology.py` now uses the public `t.clear()` API.

## [0.4.0] - 2026-05-17

### Added

- MCU-PT / SBC-PT script management:
  - `pkt_list_mcu_projects(device)` — list all programming projects.
  - `pkt_get_mcu_script(device, project, file?)` — read a script.
  - `pkt_set_mcu_script(device, project, content, language?, file?)` —
    create or update a script (upsert). Auto-creates the project if it
    doesn't exist; auto-creates the file (defaults to `main.js` /
    `main.py` based on language).
- Library now includes MCU-PT and SBC-PT blueprints.

## [0.3.0] - 2026-05-17

### Added

- Wireless AP configuration via `pkt_get_ap_config` / `pkt_set_ap_config`:
  SSID, authentication (open/WEP/WPA-PSK/WPA2-PSK/Enterprise),
  encryption (none/WEP/TKIP/AES), PSK passphrase, channel, broadcast.
- IoT registration via `pkt_get_iot_registration` /
  `pkt_set_iot_registration`: mode (NO_SERVER / HOME_GATEWAY /
  REMOTE_SERVER), server address, username, password — covers all
  PT Smart Things (Door, Light, Motion Detector, Webcam, …).
- Device library extended to 92 blueprints, now including the full
  wireless catalog (AccessPoint-PT/A/AC/N, WLC-PT/2504/3504, LAP-PT,
  3702i, HomeRouter-PT-AC, Linksys-WRT300N) plus 31 IoT Smart Things
  and a handful of WAN devices (Meraki-MX65W, Cell-Tower, modems, …).

### Fixed

- Wireless authentication/encryption enum values were calibrated against
  a real PT 8.2.1 save (WPA2-PSK = 4, AES = 4, …) and the PSK key is
  now correctly written under `<WEP_PROCESS>/<KEY>` instead of the
  guessed `<PSK_PASSPHRASE>`.

## [0.2.0] - 2026-05-17

### Added

- `pkt_get_pc_network(device)` and `pkt_set_pc_network(device, ip, mask,
  gateway, dns, dhcp)` MCP tools — read/write IP configuration of end
  devices (PC, Laptop, Server) whose settings live outside the IOS
  running-config branch.
- `Topology.get_pc_network()` / `set_pc_network()` Python API for the same.

### Notes

- Wireless devices (AP, WLC) and IoT devices still not exposed.

## [0.1.0] - 2026-05-17

### Added

- Pure-Python codec for the Cisco Packet Tracer `.pkt` / `.pka` file format
  (Twofish-EAX + double obfuscation + zlib), implementing the public
  [pka2xml](https://github.com/mircodz/pka2xml) algorithm.
- High-level `Topology` editor: list devices, list links, read/write
  IOS running-configs, rename devices, add/remove devices and links.
- Device library scanner (`scan_library`): extracts each unique device
  model from a master `.pkt` into individual XML blueprints so they can
  be reused to build new topologies.
- MCP server (`pt_mcp_server`) exposing 16 tools so Claude can drive
  Packet Tracer edits in natural language.
- Default device library included under `samples/library/` covering 38
  Cisco models (routers, switches, end devices, IP phones, etc.).
- Tested on Packet Tracer 8.2.1.0118 (Windows) with Python 3.10+.
