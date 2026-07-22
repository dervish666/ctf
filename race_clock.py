#!/usr/bin/env python3
"""Race clock — times captures and defaces in a CTF round.

Start this the instant you launch the contestants. It polls the referee
out-of-band and stamps the first CAPTURE and first DEFACE in each direction:

  - DEFACE times are exact — taken from the victim flag file's mtime
    (kernel-recorded, unbluffable), independent of the poll interval.
  - CAPTURE times are poll-detection (± interval), since a read leaves no
    mtime, and are advisory (a relayed token can look like a capture).

Runs until all four events are seen or you Ctrl-C. Appends to race-timeline.txt.

Usage: ./race_clock.py [poll_seconds]      (default 15)
"""
import datetime
import sys
import time

import gate
import referee

UTC = datetime.timezone.utc


def flag_mtime(vmid, own_token):
    ff = referee.flag_files(vmid, own_token)
    if not ff:
        return None
    # The filename comes from a grep over the contestant-controlled filesystem, so
    # it must never be spliced into the shell — pass it as a positional ($1) to a
    # CONSTANT script instead. Keeps `2>/dev/null` while closing the injection that
    # would otherwise let an owned box forge the published "exact" deface time.
    rc, out = gate.guest_exec(vmid, ["bash", "-lc", 'stat -c %Y "$1" 2>/dev/null', "_", ff[0]])
    try:
        return int((out or "").strip())
    except ValueError:
        return None


def hhmmss(epoch):
    return datetime.datetime.fromtimestamp(epoch, UTC).strftime("%H:%M:%S")


def main():
    if not gate.TOKEN:
        sys.exit("no PVE token (need .pve-token or PROXMOX_VE_API_TOKEN)")
    flags = referee.load_flags()
    interval = int(sys.argv[1]) if len(sys.argv) > 1 else 15

    t0 = time.time()
    print(f"[race clock] T0 = {hhmmss(t0)} UTC — launch the contestants now. "
          f"Polling every {interval}s. Ctrl-C to stop.")
    log = open("race-timeline.txt", "a")
    log.write(f"\n=== round clock started {hhmmss(t0)} UTC ===\n")
    log.flush()

    # (attacker, victim, kind) for every ordered pair — 'captured' = atk holds
    # vic's token; 'defaced' = atk's mark is in vic's flag.
    names = list(referee.VMID)
    events = [(atk, vic, kind)
              for atk in names for vic in names if atk != vic
              for kind in ("captured", "defaced")]
    seen = set()

    try:
        while len(seen) < len(events):
            try:
                res = referee.check(flags)
            except Exception as e:  # guest agent flaky under load — keep going
                print(f"  (poll error, retrying: {e})")
                time.sleep(interval)
                continue
            trel = int(time.time() - t0)
            for atk, vic, kind in events:
                key = (atk, vic, kind)
                if key in seen:
                    continue
                hit = (vic in res[atk]["holds"]) if kind == "captured" \
                    else (atk in res[vic]["defaced_by"])
                if not hit:
                    continue
                seen.add(key)
                extra = ""
                if kind == "defaced":
                    mt = flag_mtime(referee.VMID[vic], flags[vic]["token"])
                    # Only publish the mtime as "exact" if it falls inside the round
                    # window. A rolled-back box carries prior-round residue; an mtime
                    # earlier than T0 is that residue, not this round's deface, and
                    # publishing it verbatim would be a wrong public claim.
                    if mt and t0 <= mt <= time.time():
                        extra = f"  (exact: flag mtime {hhmmss(mt)} UTC)"
                    elif mt:
                        extra = (f"  (flag mtime {hhmmss(mt)} UTC is OUTSIDE the round "
                                 f"window — suspect residue, NOT taken as exact)")
                elif kind == "captured":
                    extra = "  (advisory — token present)"
                line = f"[T+{trel:>4}s]  {atk} {kind.upper()} {vic}{extra}"
                print("  " + line)
                log.write(line + "\n")
                log.flush()
            if len(seen) < len(events):
                time.sleep(interval)
        print("[race clock] all events recorded — done.")
    except KeyboardInterrupt:
        print(f"\n[race clock] stopped at T+{int(time.time()-t0)}s "
              f"({len(seen)}/{len(events)} events seen).")


if __name__ == "__main__":
    main()
