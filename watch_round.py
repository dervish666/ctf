#!/usr/bin/env python3
"""watch_round.py — live host-truth event watcher for the arena replay timeline.

Polls the referee (captures / defaces) and the shared channel continuously and
records every NEW event with a runtime wall-clock timestamp. This is the
ground-truth marker track that overlays on the per-contestant session replays
(the Claude Code JSONL transcripts) — so you can scrub to "the capture" or
"the con" and watch it fire across all three panes.

Unlike `referee.py --watch` (which stops at the first hit), this runs until
Ctrl-C, so it captures the WHOLE arc.

Usage — start it at kickoff, unbuffered:
  PROXMOX_VE_API_TOKEN=... python3 -u watch_round.py rounds/roundN/events.jsonl 8

Writes JSONL events (one per line) to the given path and prints a readable
line per event to stdout.
"""
import sys, time, json, datetime, subprocess
import arena_config
import gate, referee

HOST = arena_config.require("bastion")
CHANNEL = "/srv/ctf-comms/channel.md"
OUTPATH = sys.argv[1] if len(sys.argv) > 1 else "events.jsonl"
INTERVAL = int(sys.argv[2]) if len(sys.argv) > 2 else 8


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


def emit(out, kind, actor, target, detail):
    ev = {"t": now_iso(), "kind": kind, "actor": actor, "target": target, "detail": detail}
    out.write(json.dumps(ev) + "\n")
    out.flush()
    print(f"{ev['t']}  {kind:<8} {detail}", flush=True)


def channel_lines():
    """Line count of the shared channel. RAISES on failure — a swallowed error
    here silently drops every channel marker from the published timeline for the
    whole round (the caller surfaces it on transition, so no flood)."""
    r = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", HOST,
         f"wc -l < {CHANNEL} 2>/dev/null"],
        capture_output=True, timeout=20)
    if r.returncode != 0:
        raise RuntimeError(f"ssh rc={r.returncode}: {r.stderr.decode()[:120].strip()}")
    return int((r.stdout.decode().strip() or "0"))


def main():
    if not gate.TOKEN:
        sys.exit("PROXMOX_VE_API_TOKEN / .pve-token not set")
    flags = referee.load_flags()
    seen_cap, seen_def = set(), set()
    out = open(OUTPATH, "a", buffering=1)
    chan_ok = True
    try:
        last_lines = channel_lines()
    except Exception as e:
        last_lines, chan_ok = 0, False
        emit(out, "error", None, None, f"channel read failing: {str(e)[:120]}")
    emit(out, "start", None, None,
         f"watching {list(referee.VMID)} every {INTERVAL}s; channel at {last_lines} lines")
    while True:
        try:
            res = referee.check(flags)
            for n in res:
                for o in res[n]["holds"]:            # n holds o's token => n captured o
                    if (n, o) not in seen_cap:
                        seen_cap.add((n, o))
                        emit(out, "capture", n, o, f"{n} captured {o}'s flag")
                for o in res[n]["defaced_by"]:        # o's mark in n's flag => o defaced n
                    if (o, n) not in seen_def:
                        seen_def.add((o, n))
                        emit(out, "deface", o, n, f"{o} defaced {n}'s flag")
        except KeyboardInterrupt:
            break
        except Exception as e:
            emit(out, "error", None, None, str(e)[:140])
        # Channel read in its own guard so a bastion outage SURFACES (once, on
        # transition to failing, once on recovery) instead of vanishing.
        try:
            cl = channel_lines()
            if not chan_ok:
                emit(out, "note", None, None, "channel read recovered")
                chan_ok = True
            if cl > last_lines:
                emit(out, "channel", None, None, f"channel +{cl - last_lines} lines (now {cl})")
                last_lines = cl
        except KeyboardInterrupt:
            break
        except Exception as e:
            if chan_ok:
                emit(out, "error", None, None, f"channel read failing: {str(e)[:120]}")
                chan_ok = False
        time.sleep(INTERVAL)


if __name__ == "__main__":
    main()
