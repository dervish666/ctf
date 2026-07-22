#!/usr/bin/env python3
"""pull_transcripts.py — grab each contestant's Claude Code session transcript.

The transcripts (~/.claude/projects/-root/*.jsonl) are the arena's replay
source: a runtime-timestamped stream of every message, thinking block, tool
call, and result — richer and more trustworthy than the self-reported
history.md (the runtime stamps the time, not the model). No box-side recorder
needed; Claude Code writes these automatically.

Pull them at ROUND END, BEFORE any rollback wipes the box.

  python3 pull_transcripts.py rounds/roundN
"""
import subprocess, json, base64, os, sys
import arena_config

HOST = arena_config.require("bastion")
VMID = {"ctf-1": 201, "ctf-2": 202, "ctf-3": 203}
OUT = os.path.join(sys.argv[1] if len(sys.argv) > 1 else ".", "transcripts")


def ssh(cmd, t=120):
    return subprocess.check_output(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=10", HOST, cmd], timeout=t)


def _pull(name, vmid):
    """Pull + verify one box's transcripts. Raises on ANY integrity doubt.

    These are the irreplaceable record and the box is rolled away right after, so
    a truncated/corrupt pull must be LOUD, not a plausible count printed as success.
    The guest-agent exec buffer is size-capped, so a big transcript set can
    truncate — checked three ways: the agent's own out-truncated flag, base64
    integrity, and a `tar tzf` listing before we trust the extracted count.
    """
    cmd = (f"qm guest exec {vmid} --timeout 60 -- bash -lc "
           "\"cd /root/.claude/projects/-root 2>/dev/null && "
           "tar czf - *.jsonl 2>/dev/null | base64 -w0\"")
    d = json.loads(ssh(cmd))
    b64 = (d.get("out-data") or "").strip()
    if d.get("out-truncated") or d.get("err-truncated"):
        raise RuntimeError("guest agent reported TRUNCATED output — the pull is "
                           "incomplete; the transcript exceeds the exec buffer.")
    if not b64:
        print(f"{name}: no transcripts on box")
        return
    sub = os.path.join(OUT, name)
    os.makedirs(sub, exist_ok=True)
    tgz = os.path.join(sub, "t.tgz")
    try:
        raw = base64.b64decode(b64, validate=True)
    except Exception as e:
        raise RuntimeError(f"base64 decode failed ({e}) — pull is corrupt")
    with open(tgz, "wb") as fh:
        fh.write(raw)
    # A truncated .tar.gz decodes fine but fails to list/extract — this is the
    # silent-loss trap the old `check=False` walked straight into.
    listing = subprocess.run(["tar", "tzf", tgz], capture_output=True, text=True)
    if listing.returncode != 0:
        raise RuntimeError(f"archive corrupt/truncated (tar tzf rc={listing.returncode}: "
                           f"{listing.stderr.strip()[:160]})")
    ext = subprocess.run(["tar", "xzf", tgz, "-C", sub], capture_output=True, text=True)
    if ext.returncode != 0:
        raise RuntimeError(f"extraction failed (rc={ext.returncode}: {ext.stderr.strip()[:160]})")
    os.remove(tgz)
    n = len([f for f in os.listdir(sub) if f.endswith(".jsonl")])
    print(f"{name}: {n} transcript(s) -> {sub}")


def main():
    os.makedirs(OUT, exist_ok=True)
    failures = []
    for name, vmid in VMID.items():
        try:
            _pull(name, vmid)
        except Exception as e:
            print(f"{name}: FAILED — {e}")
            failures.append(name)
    if failures:
        # Non-zero exit + explicit warning: these boxes must NOT be rolled back
        # until re-pulled, or the record is lost for good.
        sys.exit(f"\n!! transcript pull INCOMPLETE for: {', '.join(failures)}. "
                 f"Do NOT roll those boxes back — re-pull manually first.")
    print("\nAll transcripts pulled and archives verified — safe to roll back.")


if __name__ == "__main__":
    main()
