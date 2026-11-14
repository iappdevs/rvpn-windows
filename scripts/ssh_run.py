#!/usr/bin/env python3
"""Tiny SSH runner for the rVPN test server (params via env)."""
import os
import sys

import paramiko

HOST = os.environ.get("RVPN_HOST", "91.107.154.88")
USER = os.environ.get("RVPN_USER", "root")
PASSWORD = os.environ["RVPN_PASS"]


def run(cmd: str, timeout: int = 120) -> int:
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(HOST, username=USER, password=PASSWORD, timeout=20)
    try:
        stdin, stdout, stderr = client.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        code = stdout.channel.recv_exit_status()
        if out:
            print(out, end="" if out.endswith("\n") else "\n")
        if err:
            print("[stderr]", err, file=sys.stderr, end="" if err.endswith("\n") else "\n")
        return code
    finally:
        client.close()


if __name__ == "__main__":
    command = sys.stdin.read()
    sys.exit(run(command))
