#!/usr/bin/env bash
# Launcher for the Packet Tracer MCP server (Linux / macOS).
set -euo pipefail
cd "$(dirname "$0")"
export PYTHONPATH="$(pwd)/src${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m pt_mcp_server.server
