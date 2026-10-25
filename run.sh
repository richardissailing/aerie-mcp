#!/bin/bash
# Lambda handler: the Web Adapter layer starts this and proxies invocations to port 8080.
exec python3 -m uvicorn falcon_fleet_mcp.app:app --host 127.0.0.1 --port "${AWS_LWA_PORT:-8080}" --no-access-log
