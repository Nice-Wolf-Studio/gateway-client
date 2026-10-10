"""End to end against the REAL mcp-gateway (`development`, contract v2): see
`gateway_e2e_driver.py`. Needs a checkout of Nice-Wolf-Studio/mcp-gateway
(private) with its requirements installed, and an empty Postgres:

    MCP_GATEWAY_DIR=../mcp-gateway TEST_DATABASE_URL=postgresql://... \\
        python -m pytest tests/test_gateway_e2e.py

Skipped when either variable is unset (this repository's CI has no access to
the private gateway repository)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

GATEWAY_DIR = os.environ.get("MCP_GATEWAY_DIR", "")
DATABASE = os.environ.get("TEST_DATABASE_URL", "")


@pytest.mark.skipif(not (GATEWAY_DIR and DATABASE),
                    reason="MCP_GATEWAY_DIR and TEST_DATABASE_URL are not set")
def test_library_against_the_real_gateway():
    driver = Path(__file__).resolve().parent / "gateway_e2e_driver.py"
    proc = subprocess.run([sys.executable, str(driver)], capture_output=True, text=True,
                          timeout=300, env={**os.environ, "MCP_GATEWAY_DIR": GATEWAY_DIR,
                                            "TEST_DATABASE_URL": DATABASE})
    start = proc.stdout.find("{")
    checks = json.loads(proc.stdout[start:]) if start >= 0 else {}
    failed = {name: c["detail"] for name, c in checks.items() if not c["ok"]}
    assert proc.returncode == 0 and checks and not failed, (
        f"exit {proc.returncode}; failed checks: {failed}\n{proc.stderr[-3000:]}")
    assert len(checks) >= 15
