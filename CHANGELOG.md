# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
