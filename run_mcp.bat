@echo off
REM Launcher for the Packet Tracer MCP server.
cd /d "%~dp0"
set PYTHONPATH=%~dp0src;%PYTHONPATH%
python -m pt_mcp_server.server
