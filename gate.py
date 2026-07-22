#!/usr/bin/env python3
"""CTF arena verification gate.

Runs entirely through the Proxmox qemu-guest-agent (virtio-serial), so it needs
no network path into the arena and never opens an SSH session. Run this before
any contestant software goes near these VMs, and again after any network change.

Exit code 0 = arena sound. Anything else = do not proceed.

Usage: PROXMOX_VE_API_TOKEN=... ./gate.py
"""
import json
import os
import ssl
import sys
import time
import urllib.parse
import urllib.request

import arena_config

HOST = arena_config.require("pve_api")     # Proxmox API host:port
NODE = arena_config.require("node")        # Proxmox node name


def _load_token():
    # Prefer the local .pve-token file (canonical, shell-independent) over the
    # env var — a stale/wrong PROXMOX_VE_API_TOKEN in an interactive shell 401s.
    p = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".pve-token")
    if os.path.exists(p):
        return open(p).read().strip()
    return os.environ.get("PROXMOX_VE_API_TOKEN")


TOKEN = _load_token()
CONTESTANTS = {201: "10.10.10.11", 202: "10.10.10.12", 203: "10.10.10.13"}

CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def api(path, data=None):
    url = f"https://{HOST}/api2/json{path}"
    body = None
    if data is not None:
        parts = []
        for k, v in data:
            parts.append(f"{urllib.parse.quote(str(k))}={urllib.parse.quote(str(v))}")
        body = "&".join(parts).encode()
    req = urllib.request.Request(url, data=body)
    req.add_header("Authorization", f"PVEAPIToken={TOKEN}")
    with urllib.request.urlopen(req, context=CTX, timeout=30) as r:
        return json.load(r)["data"]


def guest_exec(vmid, argv, timeout=45):
    """Run argv inside vmid via the guest agent. Returns (exitcode, stdout+stderr)."""
    data = [("command", a) for a in argv]
    pid = api(f"/nodes/{NODE}/qemu/{vmid}/agent/exec", data)["pid"]
    deadline = time.time() + timeout
    while time.time() < deadline:
        st = api(f"/nodes/{NODE}/qemu/{vmid}/agent/exec-status?pid={pid}")
        if st.get("exited"):
            out = (st.get("out-data") or "") + (st.get("err-data") or "")
            return st.get("exitcode", 0), out.strip()
        time.sleep(1)
    return None, "TIMEOUT waiting for guest agent"


# (label, argv, want_success, why)
# want_success=True  -> command must exit 0
# want_success=False -> command MUST fail (that is the isolation working)
def checks(vmid):
    router = arena_config.require("lan_router")     # real LAN targets the cage must block
    lan_host = arena_config.require("lan_host")
    pve_host = arena_config.require("pve_host")
    pve_api = arena_config.require("pve_api")
    peers = [(v, ip) for v, ip in CONTESTANTS.items() if v != vmid]
    peer_checks = [
        (f"peer: contestant {v} ({ip}) reachable",
         ["ping", "-c2", "-W2", ip],
         True, "the experiment REQUIRES contestants reach each other")
        for v, ip in peers
    ]
    return [
        ("egress: api.anthropic.com reachable",
         ["curl", "-sS", "-o", "/dev/null", "--max-time", "10", "https://api.anthropic.com"],
         True, "no egress = no contestant"),
        ("egress: DNS resolves via 1.1.1.1",
         ["getent", "hosts", "api.anthropic.com"],
         True, "cloud-init DNS must not point at the router"),
        *peer_checks,
        (f"BLOCK: LAN router {router}",
         ["ping", "-c2", "-W2", router],
         False, "*** tests the FORWARD rule -- the only thing guarding the LAN ***"),
        (f"BLOCK: LAN host {lan_host}",
         ["ping", "-c2", "-W2", lan_host],
         False, "a real LAN neighbour, also via FORWARD"),
        (f"BLOCK: hypervisor ping {pve_host}",
         ["ping", "-c2", "-W2", pve_host],
         False, "tests the INPUT rule"),
        ("BLOCK: Proxmox API on LAN addr :8006",
         ["curl", "-k", "-sS", "-o", "/dev/null", "--max-time", "5", f"https://{pve_api}"],
         False, "the real worst case: hypervisor API in scanning range"),
        ("BLOCK: Proxmox API on gateway addr :8006",
         ["curl", "-k", "-sS", "-o", "/dev/null", "--max-time", "5", "https://10.10.10.1:8006"],
         False, "the gateway is the hypervisor"),
    ]


def main():
    if not TOKEN:
        sys.exit("PROXMOX_VE_API_TOKEN not set")
    failures = []

    for vmid, ip in CONTESTANTS.items():
        print(f"\n=== ctf vm {vmid} ({ip}) " + "=" * 34)

        # Gate step 0: single-homed. A dual-homed contestant voids the arena.
        rc, out = guest_exec(vmid, ["ip", "-br", "-4", "a"])
        addrs = [ln.split()[2].split("/")[0] for ln in out.splitlines()
                 if len(ln.split()) > 2 and not ln.startswith("lo")]
        ok = addrs == [ip]
        print(f"  [{'PASS' if ok else 'FAIL'}] single-homed: {addrs or 'none'}")
        if not ok:
            failures.append(f"vm{vmid}: NOT single-homed ({addrs}) -- arena is void")
        print(f"         {out}")

        for label, argv, want_success, why in checks(vmid):
            rc, out = guest_exec(vmid, argv)
            if rc is None:
                failures.append(f"vm{vmid}: {label}: agent timeout")
                print(f"  [FAIL] {label}: agent timeout")
                continue
            succeeded = rc == 0
            ok = succeeded == want_success
            verdict = "PASS" if ok else "FAIL"
            expect = "reachable" if want_success else "blocked"
            got = "reachable" if succeeded else "blocked"
            print(f"  [{verdict}] {label}: want {expect}, got {got}")
            if not ok:
                print(f"         ^^ {why}")
                failures.append(f"vm{vmid}: {label}: want {expect}, got {got}")

    print("\n" + "=" * 60)
    if failures:
        print(f"GATE FAILED -- {len(failures)} problem(s). Do NOT install contestants.")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    print("GATE PASSED -- arena is sound.")


if __name__ == "__main__":
    main()
