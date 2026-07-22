#!/usr/bin/env python3
"""live_feed.py — push a running round to the public live page.

Reads the same host-side sources the replay is built from, redacts every line
through live_redact.py's prove-or-drop gate, holds it for a broadcast delay, and
POSTs it to the site. Nothing reaches the public that has not been proven clean.

Transport is the qemu guest agent (gate.guest_exec), not SSH — contestants harden
their machines and may firewall sshd off entirely, and a feed that dies the moment
an agent does its job would be a poor instrument.

    # rehearse the whole pipeline against a finished round, no arena needed
    ./live_feed.py replay ../rounds/round13 --speed 60 --dry-run
    ./live_feed.py replay ../rounds/round13 --speed 60

    # the real thing
    PROXMOX_VE_API_TOKEN=... ./live_feed.py live round14 --title "Round 14" --minutes 60

    # stop it
    ./live_feed.py kill --note "pulled while I check something"
    ./live_feed.py end

The delay is the point. Redaction is a deny-list, and a deny-list cannot know
about a secret format nobody has thought of yet. The delay is the window in which
a human can notice and reach for `kill`, which deletes what was published rather
than merely hiding it.
"""
import argparse
import collections
import re
import json
import os
import sys
import time
import urllib.error
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)
sys.path.insert(0, REPO)

from live_redact import LiveRedactor                     # noqa: E402
from build_replay import parse, summarize_tool, block_text, parse_iso  # noqa: E402

SITE = os.environ.get("ARENA_SITE", "https://ctf.scratch-it.co.uk")
BOXES = ["ctf-1", "ctf-2", "ctf-3"]
VMID = {"ctf-1": 201, "ctf-2": 202, "ctf-3": 203}
TRANSCRIPT_GLOB = "/root/.claude/projects/-root/*.jsonl"
CHANNEL = "/srv/ctf-comms/channel.md"          # host-side backing store
CHANNEL_IN_BOX = "/mnt/comms/channel.md"       # where the SAME file is mounted inside each box
PUSH_EVERY_S = 3
MAX_BATCH = 200
TRUNC = 900          # tool OUTPUT cap — a 40KB `cat` dump is not watchable
TRUNC_NARRATIVE = 3000  # the agent's own words (think/say/prompt) — worth reading in full-ish


def feed_token():
    tok = os.environ.get("ARENA_FEED_TOKEN")
    if tok:
        return tok.strip()
    path = os.path.join(REPO, "web", ".feed-token")
    if os.path.exists(path):
        return open(path).read().strip()
    sys.exit("no feed token — set ARENA_FEED_TOKEN or write web/.feed-token")


class FeedError(Exception):
    """A push/control call failed. Raised (not SystemExit) so the caller decides:
    a failed control call is fatal, a failed event push degrades — the round runs
    on and the feed carries a gap rather than the producer dying mid-round."""


def post(path, body, token=None):
    req = urllib.request.Request(
        SITE + path,
        data=json.dumps(body).encode(),
        headers={"content-type": "application/json",
                 "authorization": "Bearer " + (token or feed_token()),
                 "origin": SITE,
                 # Cloudflare's browser-integrity check rejects urllib's default
                 # agent with a 1010 before the request ever reaches the Worker.
                 # Identify the producer honestly instead.
                 "user-agent": "arena-live-feed/1.0 (+https://ctf.scratch-it.co.uk)"},
        method="POST")
    try:
        with urllib.request.urlopen(req, timeout=30) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        raise FeedError(f"push failed: HTTP {e.code} {detail}")
    except urllib.error.URLError as e:
        raise FeedError(f"push failed: {e.reason}")


class DelayLine:
    """Holds events until their release time. The broadcast delay, and the whole
    reason a mistake is recoverable instead of published."""

    def __init__(self, delay_ms):
        self.delay_ms = delay_ms
        self.q = collections.deque()

    def add(self, event, now_ms=None):
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        self.q.append((now + self.delay_ms, event))

    def due(self, now_ms=None, drain=False):
        now = now_ms if now_ms is not None else int(time.time() * 1000)
        out = []
        while self.q and (drain or self.q[0][0] <= now):
            out.append(self.q.popleft()[1])
        return out

    def __len__(self):
        return len(self.q)


class Feed:
    """Redact, prove, delay, push. Counts what it drops, and says so out loud."""

    def __init__(self, round_id, delay_ms, dry_run=False):
        self.round_id = round_id
        self.redactor = LiveRedactor()
        self.line = DelayLine(delay_ms)
        self.dry_run = dry_run
        self.pushed = 0
        self.dropped = 0
        self.drop_reasons = collections.Counter()

    def offer(self, event, now_ms=None):
        """Redact one event. Publishes it, or drops it and records why."""
        clean, why = self.redactor.scrub_event(event)
        if clean is None:
            self.dropped += 1
            self.drop_reasons[why[:80]] += 1
            # Loud, but never echoes the offending text.
            print(f"  DROPPED {event.get('kind')}/{event.get('box')}: {why}", flush=True)
            return False
        self.line.add(clean, now_ms)
        return True

    def flush(self, now_ms=None, drain=False):
        due = self.line.due(now_ms, drain)
        if not due:
            return 0
        for i in range(0, len(due), MAX_BATCH):
            chunk = due[i:i + MAX_BATCH]
            if self.dry_run:
                for e in chunk:
                    print(f"    [dry] {e['kind']:7} {e.get('box') or '-':6} "
                          f"{str(e.get('text',''))[:90]!r}")
            else:
                # Degrade, don't die. A transient push failure loses this batch and
                # is counted, but the producer keeps tailing the round — a live feed
                # is best-effort, and a dropped batch beats a dead producer that
                # stops instrumenting a round that is still going.
                try:
                    post("/api/live/push", {"round_id": self.round_id, "events": chunk})
                    self.pushed += len(chunk)
                except FeedError as e:
                    self.dropped += len(chunk)
                    self.drop_reasons[f"push failed: {str(e)[:60]}"] += len(chunk)
                    print(f"  PUSH FAILED ({len(chunk)} events lost, feed continues) — {e}", flush=True)
                continue
            self.pushed += len(chunk)
        return len(due)

    def report(self):
        print(f"\npushed {self.pushed} events, dropped {self.dropped}")
        for why, n in self.drop_reasons.most_common(8):
            print(f"  {n:5}  {why}")


# ── event shaping ─────────────────────────────────────────────────────────
ROLE = {"think": "think", "say": "say", "run": "tool", "prompt": "say", "out": "out"}
LABEL = {"think": "…", "say": "»", "run": "$", "prompt": "»", "out": "‹out›"}


def stream_event(box, t_ms, kind, text):
    body = text.strip()
    # Narrative (what the agent thinks/says) reads in near-full; raw output stays
    # tightly capped so a huge command dump can't swamp the pane.
    cap = TRUNC_NARRATIVE if kind in ("think", "say", "prompt") else TRUNC
    if len(body) > cap:
        body = body[:cap] + f"\n… (+{len(text) - cap} more characters)"
    return {"kind": "stream", "box": box, "t": t_ms,
            "role": ROLE.get(kind, "out"), "label": LABEL.get(kind, ""), "text": body}


# ── replay mode: rehearse against a finished round ────────────────────────
def run_replay(args):
    import glob
    rd = os.path.abspath(args.round_dir)
    if not os.path.isdir(rd):
        sys.exit(f"no such round directory: {rd}")

    events = []
    for box in BOXES:
        for f in sorted(glob.glob(os.path.join(rd, "transcripts", box, "*.jsonl"))):
            for t, kind, text in parse(f):
                events.append((t, stream_event(box, t, kind, text)))

    ev_path = os.path.join(rd, "events.jsonl")
    if os.path.exists(ev_path):
        for raw in open(ev_path):
            raw = raw.strip()
            if not raw:
                continue
            try:
                d = json.loads(raw)
            except Exception:
                continue
            t = parse_iso(d["t"]) if isinstance(d.get("t"), str) else int(d.get("t", 0))
            kind = d.get("kind", "")
            if kind in ("capture", "deface"):
                events.append((t, {"kind": "truth", "t": t, "box": d.get("actor"),
                                   "event": kind, "text": d.get("detail", "")}))
            elif kind == "channel":
                events.append((t, {"kind": "channel", "t": t, "box": d.get("actor"),
                                   "text": d.get("detail", "")}))

    if not events:
        sys.exit(f"no events found under {rd} — expected transcripts/<box>/*.jsonl")
    events.sort(key=lambda x: x[0])
    t0 = events[0][0]
    span = (events[-1][0] - t0) / 1000.0
    print(f"replaying {len(events)} events spanning {span/60:.1f} min at {args.speed}x "
          f"({'dry run' if args.dry_run else 'PUSHING TO ' + SITE})")

    feed = Feed(args.round_id, delay_ms=0 if args.speed > 1 else args.delay * 1000,
                dry_run=args.dry_run)
    if not args.dry_run:
        post("/api/live/control", {"action": "start", "round_id": args.round_id,
                                   "title": args.title or f"Replay of {os.path.basename(rd)}",
                                   "ends_at": int(time.time() * 1000 + span * 1000 / args.speed),
                                   "delay_ms": 0})

    wall0 = time.time()
    for t, ev in events:
        target = wall0 + (t - t0) / 1000.0 / args.speed
        now = time.time()
        if target > now:
            time.sleep(min(target - now, 5))
        feed.offer(ev, now_ms=int(time.time() * 1000))
        feed.flush()
    feed.flush(drain=True)
    if not args.dry_run:
        post("/api/live/control", {"action": "end"})
    feed.report()


# ── live mode: tail the running arena ─────────────────────────────────────
def run_live(args):
    import gate
    import referee

    feed = Feed(args.round_id, delay_ms=args.delay * 1000)
    flags = referee.load_flags()   # for the Observed column (host-side ground truth)
    ends_at = int(time.time() * 1000 + args.minutes * 60000) if args.minutes else None
    try:
        post("/api/live/control", {"action": "start", "round_id": args.round_id,
                                   "title": args.title or args.round_id,
                                   "ends_at": ends_at, "delay_ms": args.delay * 1000})
    except FeedError as e:
        sys.exit(f"could not start the feed: {e}")
    print(f"feed live: {SITE}/live.html   (delay {args.delay}s)  ctrl-C to end")

    offsets = {b: 0 for b in BOXES}
    channel_seen = 0
    truth_seen = set()

    def guest_read(box, cmd):
        code, out = gate.guest_exec(VMID[box], ["/bin/sh", "-c", cmd], timeout=30)
        return out if code == 0 else ""

    try:
        while True:
            loop_start = time.time()

            # 1. terminals
            for box in BOXES:
                try:
                    raw = guest_read(box, f"cat {TRANSCRIPT_GLOB} 2>/dev/null | tail -c +{offsets[box] + 1}")
                except Exception as e:
                    print(f"  {box}: transcript read failed — {e}", flush=True)
                    continue
                if not raw:
                    continue
                offsets[box] += len(raw.encode(errors="replace"))
                for lineno, raw_line in enumerate(raw.splitlines()):
                    raw_line = raw_line.strip()
                    if not raw_line:
                        continue
                    try:
                        d = json.loads(raw_line)
                    except Exception:
                        # A partial trailing line is normal when tailing; rewind so
                        # the next poll re-reads it whole rather than losing it.
                        if lineno == len(raw.splitlines()) - 1:
                            offsets[box] -= len(raw_line.encode(errors="replace"))
                        continue
                    for t, kind, text in _parse_one(d):
                        feed.offer(stream_event(box, t, kind, text))

            # 2. the shared channel — what they CLAIM
            try:
                # Read via a box: the shared channel is mounted at /mnt/comms there,
                # not at the host's /srv/ctf-comms path (which is invisible inside a box).
                chan = guest_read(BOXES[0], f"cat {CHANNEL_IN_BOX} 2>/dev/null")
                lines = chan.splitlines()
                for ln in lines[channel_seen:]:
                    if ln.strip():
                        feed.offer({"kind": "channel", "t": int(time.time() * 1000),
                                    "box": _actor_of(ln), "text": ln})
                channel_seen = max(channel_seen, len(lines))
            except Exception as e:
                print(f"  channel read failed — {e}", flush=True)

            # 3. the referee — what is TRUE. This is the feed's whole point: the
            # Observed column, host-side ground truth, set against what the agents
            # CLAIM in the channel above. referee.check() returns, per box, whose
            # tokens it holds (captures) and whose marks are in its flag (defaces).
            try:
                res = referee.check(flags)
                for name in res:
                    for opp in res[name]["holds"]:        # name holds opp's token => name captured opp
                        key = ("capture", name, opp)
                        if key not in truth_seen:
                            truth_seen.add(key)
                            feed.offer({"kind": "truth", "t": int(time.time() * 1000),
                                        "box": name, "event": "capture",
                                        "text": f"{name} holds {opp}'s flag token (verify provenance)"})
                    for opp in res[name]["defaced_by"]:   # opp's mark in name's flag => opp defaced name
                        key = ("deface", opp, name)
                        if key not in truth_seen:
                            truth_seen.add(key)
                            feed.offer({"kind": "truth", "t": int(time.time() * 1000),
                                        "box": opp, "event": "deface",
                                        "text": f"{opp} defaced {name}'s flag"})
            except Exception as e:
                # NOT silent: the Observed column is the reason this page exists, so a
                # referee read failure is surfaced on the feed rather than leaving a
                # blank truth track that reads as "nothing has happened".
                print(f"  referee check failed — {e}", flush=True)
                feed.offer({"kind": "note", "t": int(time.time() * 1000),
                            "box": None, "text": f"(referee read failed — observed column may be stale: {str(e)[:60]})"})

            feed.flush()
            print(f"  [{time.strftime('%H:%M:%S')}] pushed={feed.pushed} "
                  f"held={len(feed.line)} dropped={feed.dropped}", flush=True)
            time.sleep(max(0, PUSH_EVERY_S - (time.time() - loop_start)))
    except KeyboardInterrupt:
        print("\nending — draining the delay line…")
        feed.flush(drain=True)
        try:
            post("/api/live/control", {"action": "end"})
        except FeedError as e:
            print(f"  (could not mark the feed ended: {e} — kill it from /admin if it lingers)", flush=True)
        feed.report()


def _parse_one(d):
    """build_replay.parse(), for a single already-decoded transcript line."""
    out = []
    tsr = d.get("timestamp")
    if not tsr:
        return out
    t = parse_iso(tsr)
    msg = d.get("message") or {}
    if d.get("type") == "assistant":
        for b in msg.get("content") or []:
            if not isinstance(b, dict):
                continue
            bt = b.get("type")
            if bt == "thinking" and (b.get("thinking") or "").strip():
                out.append((t, "think", b["thinking"]))
            elif bt == "text" and (b.get("text") or "").strip():
                out.append((t, "say", b["text"]))
            elif bt == "tool_use":
                out.append((t, "run", summarize_tool(b.get("name"), b.get("input"))))
    elif d.get("type") == "user":
        content = msg.get("content")
        if isinstance(content, str) and content.strip():
            out.append((t, "prompt", content))
        elif isinstance(content, list):
            for b in content:
                if isinstance(b, dict) and b.get("type") == "tool_result":
                    c = b.get("content")
                    txt = "\n".join(block_text(x) for x in c) if isinstance(c, list) else str(c or "")
                    if txt.strip():
                        out.append((t, "out", txt))
    return out


# The author's own tag ([ctf-2], (ctf-3):) — how the agents sign a channel post.
_SELF_TAG = re.compile(r'[\[(]\s*(ctf-\d)\b')
_ANY_BOX = re.compile(r'\b(ctf-\d)\b')


def _actor_of(line):
    """Who WROTE this channel line. Attribute by the author's self-tag, not by the
    first box name mentioned: a line that talks ABOUT another box ('ctf-1 is
    screaming…') was otherwise stolen by whoever it named first (and ctf-1 always
    won). A self-tag we don't recognise (e.g. an agent calling itself 'ctf-0'), or
    a line with no box reference at all (command output dumped into the channel),
    returns None rather than a wrong guess."""
    m = _SELF_TAG.search(line) or _ANY_BOX.search(line)
    box = m.group(1) if m else None
    return box if box in BOXES else None


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("replay", help="rehearse against a finished round")
    r.add_argument("round_dir")
    r.add_argument("--speed", type=float, default=60.0)
    r.add_argument("--delay", type=int, default=0)
    r.add_argument("--round-id", default="rehearsal")
    r.add_argument("--title", default=None)
    r.add_argument("--dry-run", action="store_true", help="redact and print, push nothing")

    l = sub.add_parser("live", help="stream the running arena")
    l.add_argument("round_id")
    l.add_argument("--title", default=None)
    l.add_argument("--delay", type=int, default=90, help="broadcast delay, seconds")
    l.add_argument("--minutes", type=int, default=60, help="0 for open-ended")

    k = sub.add_parser("kill", help="stop the feed AND delete what it published")
    k.add_argument("--note", default=None)

    sub.add_parser("end", help="close the feed normally")
    sub.add_parser("reset", help="back to idle")

    args = ap.parse_args()
    if args.cmd == "replay":
        run_replay(args)
    elif args.cmd == "live":
        run_live(args)
    elif args.cmd == "kill":
        print(post("/api/live/control", {"action": "kill", "note": args.note}))
    elif args.cmd == "end":
        print(post("/api/live/control", {"action": "end"}))
    elif args.cmd == "reset":
        print(post("/api/live/control", {"action": "reset"}))


if __name__ == "__main__":
    main()
