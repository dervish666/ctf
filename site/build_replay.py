#!/usr/bin/env python3
"""build_replay.py — turn a round's session transcripts into a self-contained,
scrubbable three-pane replay. Round-agnostic: point it at any rounds/roundN.

  python3 site/build_replay.py rounds/round11
  python3 site/build_replay.py rounds/round9 --out site/replay-r9.html

Reads (all relative to the round dir unless noted):
  transcripts/<box>/*.jsonl   contestant Claude Code session transcripts (REQUIRED;
                              runtime-timestamped, so the timeline is trustworthy)
  events.jsonl                host-truth marker track from watch_round.py (optional;
                              captures/defaces become ground-truth markers)
  replay-meta.json            per-round title / box roles / curated markers (optional;
                              overrides inventory + adds narrative markers)
  ../../ansible/flags.local.yml   flag tokens, for redaction
  ../../ansible/inventory.ini     fallback per-box model/effort when no meta

Emits ONE standalone HTML (default <round>/replay.html), data inlined, secrets
redacted, no external deps. Redaction is always applied and verified: the build
aborts if a known secret survives into the output.

replay-meta.json schema (every field optional):
  {
    "title": "Round 11 — the clock test",
    "markers_from_events": true,
    "boxes": [ {"id":"ctf-1","model":"Haiku 4.5","effort":"max","role":"..."} , ... ],
    "markers": [ {"t_iso":"2026-07-19T11:20:00Z","label":"first blood"},
                 {"at_s": 640, "label":"truce proposed"} ]
  }
"""
import json, os, re, sys, datetime, glob, argparse

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # ctf/
sys.path.insert(0, REPO)
import arena_config  # noqa: E402  (needs REPO on sys.path first)

IPMAP = {"ctf-1": "10.10.10.11", "ctf-2": "10.10.10.12", "ctf-3": "10.10.10.13"}
BOX_IDS = ["ctf-1", "ctf-2", "ctf-3"]
# Seeded secrets and operator PII to scrub come from gitignored arena-local config,
# never hardcoded here — this file is tracked on a public repo. If the config is
# absent these SPECIFIC scrubs are skipped (and the build warns), but the GENERIC
# patterns below (192.168.x, /Users/…, CTF{hex}, sk-ant-…) still fire regardless.
STRONG_PW = arena_config.get("strong_pw")             # disclosure-lane DB password (seeded)
REDACT_HOSTS = arena_config.get("redact_hosts", [])   # real host / laptop names
REDACT_USERS = arena_config.get("redact_users", [])   # operator username(s)
# Two caps. Tool output/channel stay tight so a spammy `curl` progress dump or a
# 65k-port scan can't bloat the file; the narrative kinds (a contestant's thinking,
# what it says, the prompt it read) carry the story, so they get room to breathe —
# matches the live feed's role-aware cap and kills the durable-replay "+N more" clip.
TRUNC = 1200
TRUNC_NARRATIVE = 3000


# ---------------------------------------------------------------- redaction ---
def load_tokens(flags_path):
    toks, cur = {}, None
    if not os.path.exists(flags_path):
        return toks
    for raw in open(flags_path):
        s = raw.strip()
        if s.startswith("ctf-") and s.endswith(":"):
            cur = s[:-1]
        elif cur and s.startswith("token:") and '"' in s:
            toks[cur] = s.split('"')[1]
    return toks


def make_redactor(tokens):
    """Every transform here must also appear in SECRET_PATTERNS below so the
    post-build verification can prove nothing leaked."""
    def redact(t):
        if not t:
            return t
        t = re.sub(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
                   "‹private-key redacted›", t, flags=re.S)
        # residual lone markers (e.g. grep output listing key files) — not secret
        # themselves, but scrub so no key-block delimiter survives into the page
        t = re.sub(r"-----(?:BEGIN|END) [A-Z ]*PRIVATE KEY-----", "‹private-key redacted›", t)
        t = re.sub(r"sk-ant-[A-Za-z0-9_\-]{6,}", "‹token-redacted›", t)
        # Other credential families an agent may print/dump. Each has a matching
        # detector in secret_patterns() so the post-build verify can PROVE they went.
        t = re.sub(r"\bAKIA[0-9A-Z]{16}\b", "‹aws-key-redacted›", t)
        t = re.sub(r"\bgh[pousr]_[A-Za-z0-9]{20,}", "‹github-token-redacted›", t)
        t = re.sub(r"\bxox[baprs]-[A-Za-z0-9-]{10,}", "‹slack-token-redacted›", t)
        t = re.sub(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}", "‹jwt-redacted›", t)
        t = re.sub(r"(?i)(bearer\s+)[A-Za-z0-9._\-]{16,}", r"\1‹token-redacted›", t)
        for name, tok in tokens.items():
            if tok:
                t = t.replace(tok, "CTF{‹%s's flag›}" % name)
        # partial / decoy flags in CTF{hex} form (e.g. a contestant printing only
        # the first bytes of a flag) — the exact-token replace above misses these
        t = re.sub(r"CTF\{[0-9a-f]{6,}\}?", "CTF{‹flag›}", t)
        if STRONG_PW:
            t = t.replace(STRONG_PW, "‹disclosure-pw›")
        # Linear email pattern. The old `[\w.+-]+@[\w.-]+\.\w{2,}` was quadratic —
        # the domain's `[\w.-]+` overlapped the following `\.`, so an ordinary long
        # terminal line (`operator@ctf-1:~$ <long cmd>`) backtracked O(n²) and, on
        # the live path, stalled the single-threaded redactor for seconds, delaying
        # the kill window. Bounding the local part and making each domain label a
        # dot-free `[\w-]+` removes the overlap and the blow-up.
        t = re.sub(r"[\w.+-]{1,64}@[\w-]+(?:\.[\w-]+)+", "‹email›", t)
        # Specific host / operator names come from gitignored config (not hardcoded
        # on a public repo). The generic 192.168 / path scrubs below are shape-based
        # and safe to publish, so they stay inline.
        for h in REDACT_HOSTS:
            if h:
                t = re.sub(re.escape(h) + r"(\.local)?", "‹host›", t, flags=re.I)
        for u in REDACT_USERS:
            if u:
                t = re.sub(r"\b" + re.escape(u) + r"\w*\b", "‹user›", t)
        t = re.sub(r"192\.168\.\d+\.\d+", "‹home-net›", t)
        # Operator/controller home paths (build_replay previously had no scrub —
        # only live_redact did — so `/home/sam` leaked into durable replays). Keep
        # the synthetic arena users (operator/app/ctf), redact real names.
        t = re.sub(r"/Users/[A-Za-z0-9._-]+", "/Users/‹user›", t)
        t = re.sub(r"/home/(?!operator\b|ctf\b|app\b)[A-Za-z0-9._-]+", "/home/‹user›", t)
        return t
    return redact


def secret_patterns(tokens):
    # One detector per credential transform in make_redactor, so a surviving secret
    # is PROVEN, not assumed. (email/host/home paths are PII-scrubs, not secrets, so
    # they are best-effort transforms without a hard verify — a stray one is not a
    # reason to abort a build, unlike a live credential.)
    pats = [r"sk-ant-[A-Za-z0-9_\-]{6,}", r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
            r"CTF\{[0-9a-f]{6,}", r"192\.168\.\d+\.\d+",
            r"\bAKIA[0-9A-Z]{16}\b", r"\bgh[pousr]_[A-Za-z0-9]{20,}",
            r"\bxox[baprs]-[A-Za-z0-9-]{10,}",
            r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{6,}"]
    # named host/user detectors come from config, so they hard-verify only when the
    # corpus is present (build() warns loudly when it isn't — see main()).
    pats += [r"\b" + re.escape(u) + r"\w*\b" for u in REDACT_USERS if u]
    pats += [re.escape(h) for h in REDACT_HOSTS if h]
    if STRONG_PW:
        pats.append(re.escape(STRONG_PW))
    pats += [re.escape(tok) for tok in tokens.values() if tok]
    return pats


# ------------------------------------------------------------- transcript ----
def parse_iso(s):
    return int(datetime.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() * 1000)


def summarize_tool(name, inp):
    inp = inp or {}
    if name == "Bash":
        return "$ " + (inp.get("command") or "").strip()
    if name in ("Read", "Write", "Edit", "NotebookEdit"):
        return name.lower() + " " + str(inp.get("file_path") or inp.get("path") or "")
    if name == "Grep":
        return "grep " + str(inp.get("pattern") or "")
    keys = " ".join(f"{k}={str(v)[:36]}" for k, v in list(inp.items())[:2])
    return name + " " + keys


def block_text(b):
    if isinstance(b, str):
        return b
    if isinstance(b, dict):
        return b.get("text") or b.get("content") or ""
    return ""


# Claude Code slash-command scaffolding that rides along in the transcript — the
# /login flow each box runs at startup wraps itself in these tags. It's harness
# noise, not contestant behaviour, so a public replay shouldn't open on
# "<command-name>/login" / "Login successful". Drop any prompt/output carrying it.
HARNESS_NOISE = re.compile(
    r'<(?:local-command-(?:caveat|stdout|stderr)|command-(?:name|message|args))>')


def parse(path):
    evs = []
    for line in open(path):
        line = line.strip()
        if not line:
            continue
        try:
            d = json.loads(line)
        except Exception:
            continue
        typ, tsr = d.get("type"), d.get("timestamp")
        if not tsr:
            continue
        t = parse_iso(tsr)
        msg = d.get("message") or {}
        if typ == "assistant":
            content = msg.get("content")
            if not isinstance(content, list):
                continue
            for b in content:
                if not isinstance(b, dict):
                    continue
                bt = b.get("type")
                if bt == "thinking" and (b.get("thinking") or "").strip():
                    evs.append((t, "think", b["thinking"]))
                elif bt == "text" and (b.get("text") or "").strip():
                    evs.append((t, "say", b["text"]))
                elif bt == "tool_use":
                    evs.append((t, "run", summarize_tool(b.get("name"), b.get("input"))))
        elif typ == "user":
            content = msg.get("content")
            if isinstance(content, str) and content.strip():
                if not HARNESS_NOISE.search(content):
                    evs.append((t, "prompt", content))
            elif isinstance(content, list):
                for b in content:
                    if isinstance(b, dict) and b.get("type") == "tool_result":
                        c = b.get("content")
                        txt = "\n".join(block_text(x) for x in c) if isinstance(c, list) else str(c or "")
                        if txt.strip() and not HARNESS_NOISE.search(txt):
                            evs.append((t, "out", txt))
    return evs


# ------------------------------------------------------------- metadata ------
def prettify_model(m):
    if not m:
        return "?"
    m = m.lower()
    if "haiku" in m:
        return "Haiku 4.5"
    if "sonnet" in m:
        return "Sonnet 5"
    if "opus" in m:
        return "Opus 4.8"
    if "fable" in m:
        return "Fable 5"
    return m


def load_inventory(inv_path):
    out = {}
    if not os.path.exists(inv_path):
        return out
    for line in open(inv_path):
        line = line.strip()
        m = re.match(r"(ctf-[123])\b", line)
        if not m or line.startswith("#"):
            continue
        kv = dict(re.findall(r"(\w+)=(\S+)", line))
        out[m.group(1)] = kv
    return out


def resolve_boxes(meta, inv):
    meta_boxes = {b["id"]: b for b in meta.get("boxes", [])}
    boxes = []
    for bid in BOX_IDS:
        mb, iv = meta_boxes.get(bid, {}), inv.get(bid, {})
        boxes.append({
            "id": bid,
            "model": mb.get("model") or prettify_model(iv.get("model", "")),
            "effort": mb.get("effort") or iv.get("effort", "?"),
            "ip": mb.get("ip") or IPMAP[bid],
            "role": mb.get("role", ""),
        })
    return boxes


def load_event_markers(events_path, start_ms, dur):
    """Ground-truth markers from watch_round.py events.jsonl (captures/defaces)."""
    mks = []
    if not os.path.exists(events_path):
        return mks
    for line in open(events_path):
        line = line.strip()
        if not line:
            continue
        try:
            e = json.loads(line)
        except Exception:
            continue
        if e.get("kind") not in ("capture", "deface"):
            continue
        t = max(0, min(dur, parse_iso(e["t"]) - start_ms))
        mks.append({"t": t, "label": e.get("detail") or f"{e.get('actor')} → {e.get('target')}"})
    return mks


def meta_markers(meta, start_ms, dur):
    mks = []
    for m in meta.get("markers", []):
        if "t_iso" in m:
            t = max(0, min(dur, parse_iso(m["t_iso"]) - start_ms))
        elif "at_s" in m:
            t = max(0, min(dur, int(m["at_s"] * 1000)))
        else:
            continue
        mks.append({"t": t, "label": m["label"]})
    return mks


def load_channel(round_dir, events_path, start_ms, dur, clean):
    """Timestamped channel posts for the shared-channel panel. Reconstructs WHEN
    each line appeared from channel.md + the line-count milestones watch_round.py
    records ('channel … now N'). Falls back to spreading lines evenly across the
    round if no milestones were captured. Content is redacted via clean()."""
    cpath = os.path.join(round_dir, "channel.md")
    if not os.path.exists(cpath):
        return []
    # Split on \n ONLY. Iterating the file (or splitlines) uses universal-newline
    # mode, which also breaks on the bare \r that a `curl` progress meter or any
    # terminal-overwrite dump is full of — one pasted progress line then explodes
    # into ~40 near-empty channel posts and floods the panel. Splitting on \n keeps
    # such a dump as a single line, which clean() then truncates.
    # newline="" disables universal-newline translation on read — otherwise the \r
    # are turned into \n before we ever split, and the split re-explodes them.
    raw = open(cpath, encoding="utf-8", errors="replace", newline="").read()
    lines = raw.split("\n")
    content = [(i, l) for i, l in enumerate(lines) if l.strip()]
    if not content:
        return []
    milestones = []
    if os.path.exists(events_path):
        for ln in open(events_path):
            try:
                e = json.loads(ln)
            except Exception:
                continue
            if e.get("kind") == "channel":
                m = re.search(r"now (\d+)", e.get("detail", ""))
                if m:
                    milestones.append((int(m.group(1)), max(0, min(dur, parse_iso(e["t"]) - start_ms))))
    milestones.sort()

    def tstamp(line_idx):                       # first milestone whose count covers this line
        for cnt, t in milestones:
            if cnt >= line_idx + 1:
                return t
        return None

    posts, n = [], len(content)
    for k, (idx, l) in enumerate(content):
        t = tstamp(idx) if milestones else None
        if t is None:                           # no milestone → spread evenly across the round
            t = int(dur * k / max(1, n - 1)) if n > 1 else 0
        posts.append({"t": t, "x": clean(l)})
    posts.sort(key=lambda p: p["t"])
    return posts


# ----------------------------------------------------------------- main ------
def main():
    ap = argparse.ArgumentParser(description="Build a scrubbable three-pane replay for a CTF round.")
    ap.add_argument("round_dir", help="e.g. rounds/round11")
    ap.add_argument("--out", help="output HTML path (default <round_dir>/replay.html)")
    ap.add_argument("--title", help="override the round title shown in the header")
    args = ap.parse_args()

    round_dir = args.round_dir if os.path.isabs(args.round_dir) else os.path.join(REPO, args.round_dir)
    if not os.path.isdir(round_dir):
        sys.exit(f"no such round dir: {round_dir}")
    rname = os.path.basename(round_dir.rstrip("/"))          # e.g. round11
    rlabel = "Round " + re.sub(r"\D", "", rname) if re.search(r"\d", rname) else rname.title()
    out = args.out or os.path.join(round_dir, "replay.html")
    tdir = os.path.join(round_dir, "transcripts")

    meta = {}
    mpath = os.path.join(round_dir, "replay-meta.json")
    if os.path.exists(mpath):
        meta = json.load(open(mpath))

    tokens = load_tokens(os.path.join(REPO, "ansible", "flags.local.yml"))
    if not tokens:
        # Not fatal here — a historical rebuild runs against whatever flags are
        # current, which may have rotated, so exact-token matching legitimately
        # finds nothing and the generic CTF{hex} net does the work. But say so,
        # loudly: a SILENT empty-tokens is how a real fail-open would hide.
        print("WARNING: no flag tokens loaded from ansible/flags.local.yml — exact-token "
              "redaction is disabled; relying on the generic CTF{hex} net only.", file=sys.stderr)
    if not REDACT_HOSTS and not REDACT_USERS:
        print("WARNING: no arena.local.json / ARENA_* config — host/operator-name redaction "
              "is disabled; the generic 192.168 / path / credential nets still apply.",
              file=sys.stderr)
    redact = make_redactor(tokens)
    inv = load_inventory(os.path.join(REPO, "ansible", "inventory.ini"))
    boxes = resolve_boxes(meta, inv)

    raw = {}
    for b in boxes:
        evs = []
        for f in sorted(glob.glob(os.path.join(tdir, b["id"], "*.jsonl"))):
            evs += parse(f)
        evs.sort(key=lambda e: e[0])
        raw[b["id"]] = evs
    if not any(raw.values()):
        sys.exit(f"no transcript events found under {tdir}/<box>/*.jsonl — pull transcripts first")

    all_t = [e[0] for evs in raw.values() for e in evs]
    start, end = min(all_t), max(all_t)
    dur = max(1, end - start)

    def clean(txt, kind=None):
        txt = redact(txt).strip()
        # drop chars that break the artifact host / JSON embed: the U+FFFD
        # replacement char (from non-UTF-8 command output), lone surrogates,
        # and C0/C1 control chars other than tab/newline
        txt = txt.replace("�", "").encode("utf-8", "ignore").decode("utf-8")
        # strip C0/C1 controls except tab/newline — now INCLUDING lone \x0d (CR):
        # a terminal-overwrite \r renders as a spurious line break under pre-wrap and
        # is never meaningful in the record. \r\n collapses to \n; lone \r vanishes.
        txt = re.sub(r"[\x00-\x08\x0b-\x0d\x0e-\x1f\x7f]", "", txt)
        cap = TRUNC_NARRATIVE if kind in ("think", "say", "prompt") else TRUNC
        return txt[:cap] + " …" if len(txt) > cap else txt

    events = {b["id"]: [{"t": t - start, "k": k, "x": clean(x, k)} for (t, k, x) in raw[b["id"]]] for b in boxes}

    # markers: round bounds + ground-truth events + curated, deduped by label
    markers = [{"t": 0, "label": "Round begins"}]
    if meta.get("markers_from_events", True):
        markers += load_event_markers(os.path.join(round_dir, "events.jsonl"), start, dur)
    markers += meta_markers(meta, start, dur)
    markers.append({"t": dur, "label": "Round ends"})
    seen, mk = set(), []
    for m in sorted(markers, key=lambda x: x["t"]):
        if m["label"] in seen:
            continue
        seen.add(m["label"])
        mk.append(m)
    markers = mk

    channel = load_channel(round_dir, os.path.join(round_dir, "events.jsonl"), start, dur, clean)

    title = args.title or meta.get("title") or f"{rlabel} — the arena"
    DATA = {
        "meta": {
            "round": title,
            "start": datetime.datetime.fromtimestamp(start / 1000, datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
            "dur": dur,
            "boxes": boxes,
        },
        "events": events,
        "markers": markers,
        "channel": channel,
    }

    payload = json.dumps(DATA, ensure_ascii=False)

    # verification: no known secret may survive into the emitted payload
    leaks = []
    for pat in secret_patterns(tokens):
        if re.search(pat, payload):
            leaks.append(pat[:40])
    if leaks:
        sys.exit("ABORT — secret survived redaction into payload: " + ", ".join(leaks))

    html = HTML.replace("__ROUNDNAME__", rlabel).replace("__DATA__", payload)
    open(out, "w").write(html)
    total = sum(len(v) for v in events.values())
    print(f"{rname}: boxes={[(b['id'], len(events[b['id']])) for b in boxes]}")
    print(f"span={dur/1000:.0f}s events={total} markers={len(markers)} channel={len(channel)} -> {out} ({os.path.getsize(out)//1024}K, no secrets)")


HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>The Arena — __ROUNDNAME__ Replay</title>
</head>
<body>
<style>
  :root{
    --bg:#0b0f13; --panel:#0f161c; --inset:#0a0e12; --border:#212c35; --border-b:#31404b;
    --text:#dfe6ec; --dim:#8fa0ac; --faint:#70818c;
    --amber:#e8a33d; --run:#63c2b4; --think:#8a7fb8; --capture:#e0655b; --say:#cfd8de;
  }
  *,*::before,*::after{box-sizing:border-box}
  html,body{height:100%}
  body{margin:0; background:var(--bg); color:var(--text);
    font-family:"Iowan Old Style",Palatino,Georgia,serif;
    display:flex; flex-direction:column; overflow:hidden}
  .mono{font-family:ui-monospace,"SF Mono","JetBrains Mono",Menlo,Consolas,monospace}
  :focus-visible{outline:2px solid var(--amber); outline-offset:2px}

  .rhead{flex:none; padding:12px clamp(14px,3vw,26px); border-bottom:1px solid var(--border);
    display:flex; align-items:center; gap:18px; flex-wrap:wrap; background:var(--panel)}
  .rhead .sig{width:8px;height:8px;border-radius:50%;background:var(--amber);animation:ping 2.6s ease-out infinite;flex:none}
  @keyframes ping{0%{box-shadow:0 0 0 0 rgba(232,163,61,.5)}70%,100%{box-shadow:0 0 0 7px transparent}}
  .rhead h1{font-size:1rem; font-weight:600; margin:0; letter-spacing:.01em}
  .rhome{position:relative; display:inline-flex; align-items:center; gap:9px; color:var(--text); border:0; text-decoration:none;
    font-size:1rem; font-weight:600; letter-spacing:.01em; transition:color .15s}
  .rhome::after{content:""; position:absolute; inset:-10px 0}
  .rhome:hover{color:var(--amber); text-decoration:underline; text-underline-offset:3px}
  .rhome::before{content:"‹"; color:var(--faint); font-size:1.1rem; margin-right:1px}
  .rhome:hover::before{color:var(--amber)}
  .rhead .sub{font-size:.72rem; letter-spacing:.14em; text-transform:uppercase; color:var(--faint)}
  .filters{display:flex; gap:7px; margin-left:auto; flex-wrap:wrap; align-items:center}
  .filters .flabel{font-size:.62rem; letter-spacing:.13em; text-transform:uppercase; color:var(--faint); margin-right:2px}
  .flt{position:relative; display:inline-flex; align-items:center; gap:6px; cursor:pointer;
    font-family:ui-monospace,Menlo,monospace; font-size:.64rem; letter-spacing:.08em; text-transform:uppercase;
    color:var(--dim); background:var(--inset); border:1px solid var(--border); border-radius:100px; padding:5px 11px;
    transition:opacity .15s, border-color .15s, color .15s}
  /* 24px pill, 44px touch target — expanded vertically so neighbours never overlap */
  .flt::after{content:""; position:absolute; inset:-10px -2px}
  .flt i{width:9px;height:9px;border-radius:2px;display:inline-block}
  .flt:hover{border-color:var(--border-b); color:var(--text)}
  .flt[aria-pressed="false"]{opacity:.42; text-decoration:line-through; text-decoration-thickness:1px}

  .noscript-note{flex:none; margin:0; padding:14px clamp(14px,3vw,26px); border-bottom:1px solid var(--border-b);
    background:var(--inset); color:var(--text); font-size:.92rem; line-height:1.5}
  .noscript-note a{color:var(--amber)}
  .stage{flex:1; min-height:0; display:grid; grid-template-columns:repeat(3,1fr); gap:1px; background:var(--border)}
  .pane{background:var(--panel); min-width:0; display:flex; flex-direction:column; min-height:0}
  .pane > header{flex:none; padding:9px 14px; border-bottom:1px solid var(--border);
    display:flex; align-items:baseline; gap:9px; background:var(--inset)}
  .pane h2{margin:0; font-size:.82rem; letter-spacing:.09em; text-transform:uppercase; font-family:ui-monospace,Menlo,monospace}
  .pane .who{font-size:.66rem; color:var(--dim)}
  .pane .role{margin-left:auto; font-size:.64rem; font-style:italic; color:var(--faint)}
  .c1 h2{color:var(--say)} .c2 h2{color:var(--amber)} .c3 h2{color:var(--think)}
  /* No scroll-behavior:smooth here. render() re-targets scrollTop every frame, which restarts a
     smooth animation before it can advance — the panes then never follow the newest line at all. */
  .stream{flex:1; min-height:0; overflow-y:auto; padding:12px 14px 40px;
    font-family:ui-monospace,"SF Mono",Menlo,Consolas,monospace; font-size:12px; line-height:1.5}
  .stream::-webkit-scrollbar{width:8px} .stream::-webkit-scrollbar-thumb{background:var(--border-b); border-radius:4px}

  /* content-visibility lets the browser skip layout for offscreen lines: on a 962-event round it
     roughly halves the cost of a scrub. Still findable by find-in-page and present to a screen reader. */
  .ev{display:none; margin:0 0 9px; white-space:pre-wrap; word-break:break-word;
    content-visibility:auto; contain-intrinsic-size:auto 18px}
  .ev.on{display:block; animation:fade .25s ease both}
  @keyframes fade{from{opacity:0}to{opacity:1}}
  .ev .ts{color:var(--faint); font-size:10px; margin-right:8px; user-select:none}
  .ev--think{color:var(--think); font-style:italic; opacity:.92; border-left:1px solid rgba(138,127,184,.55); padding-left:9px}
  .ev--think .lbl{font-style:normal; font-size:9px; letter-spacing:.12em; text-transform:uppercase; opacity:.7; margin-right:6px}
  .ev--say{color:var(--say)}
  .ev--run{color:var(--run)}
  .ev--prompt{color:var(--amber); font-weight:600}
  .ev--out{color:var(--dim); background:var(--inset); border:1px solid var(--border); border-radius:3px; padding:6px 9px; font-size:11px; max-height:15em; overflow:auto}

  .controls{flex:none; display:flex; align-items:center; gap:14px; padding:12px clamp(14px,3vw,26px);
    border-top:1px solid var(--border); background:var(--panel)}
  .pbtn{position:relative;width:38px;height:38px;flex:none;border-radius:50%;border:1px solid var(--border-b);background:var(--inset);
    color:var(--amber);font-size:14px;cursor:pointer;display:grid;place-items:center;transition:background .15s}
  .pbtn::after{content:"";position:absolute;inset:-3px}
  .pbtn:hover{background:#131c23}
  .track{position:relative; flex:1; min-width:0; height:34px; display:flex; align-items:center}
  /* 4px visual bar, 24px grabbable input: the track is drawn by the pseudo-element, not the box. */
  .scrub{-webkit-appearance:none;appearance:none;width:100%;height:24px;
    background:transparent;outline-offset:4px;margin:0;cursor:pointer}
  .scrub::-webkit-slider-runnable-track{height:4px;border-radius:3px;background:var(--border-b)}
  .scrub::-moz-range-track{height:4px;border-radius:3px;background:var(--border-b)}
  .scrub::-webkit-slider-thumb{-webkit-appearance:none;width:15px;height:15px;border-radius:50%;background:var(--amber);cursor:pointer;border:2px solid var(--bg);margin-top:-5.5px}
  .scrub::-moz-range-thumb{width:15px;height:15px;border-radius:50%;background:var(--amber);cursor:pointer;border:2px solid var(--bg)}
  .markers{position:absolute; left:0; right:0; top:0; height:100%; pointer-events:none}
  .mk{position:absolute; top:0; height:100%; transform:translateX(-50%); pointer-events:auto}
  .mk i{position:absolute; top:3px; left:50%; transform:translateX(-50%); width:2px; height:9px; background:var(--capture); border-radius:2px}
  .mk button{position:absolute;inset:0;width:24px;left:-12px;background:none;border:0;cursor:pointer}
  .mk .tip{position:absolute; bottom:26px; left:50%; transform:translateX(-50%); white-space:nowrap;
    font-family:ui-monospace,Menlo,monospace; font-size:10px; letter-spacing:.04em; color:var(--text);
    background:var(--inset); border:1px solid var(--border-b); border-radius:3px; padding:3px 7px;
    opacity:0; transition:opacity .15s; pointer-events:none}
  .mk:hover .tip,.mk:focus-within .tip{opacity:1}
  .clock{flex:none; font-family:ui-monospace,Menlo,monospace; font-size:12px; color:var(--dim); font-variant-numeric:tabular-nums; min-width:150px; text-align:right}
  .clock b{color:var(--amber); font-weight:500}
  .speed{flex:none; background:var(--inset); color:var(--dim); border:1px solid var(--border); border-radius:4px;
    padding:6px 8px; font-family:ui-monospace,Menlo,monospace; font-size:11px}

  /* shared channel — full-width panel across the bottom, under all three panes */
  .chan{flex:none; display:flex; flex-direction:column; border-top:1px solid var(--border-b); background:var(--panel); max-height:26vh}
  .chan > header{flex:none; padding:8px 14px; border-bottom:1px solid var(--border); background:var(--inset);
    display:flex; align-items:center; gap:9px; font-family:ui-monospace,Menlo,monospace;
    font-size:.66rem; letter-spacing:.12em; text-transform:uppercase; color:var(--faint)}
  .chan .csig{width:7px;height:7px;border-radius:50%;background:var(--run);flex:none}
  .chan .cnote{margin-left:auto; font-style:italic; text-transform:none; letter-spacing:0; font-family:"Iowan Old Style",Palatino,Georgia,serif}
  .chanlog{flex:1; min-height:0; overflow-y:auto; padding:10px 14px 16px; font-size:11.5px; line-height:1.5}
  .chanlog::-webkit-scrollbar{width:8px} .chanlog::-webkit-scrollbar-thumb{background:var(--border-b);border-radius:4px}
  .cln{display:none; white-space:pre-wrap; word-break:break-word; color:var(--say); margin:0 0 1px;
    content-visibility:auto; contain-intrinsic-size:auto 17px}
  .cln.on{display:block; animation:fade .25s ease both}
  .cln .ts{color:var(--faint); font-size:10px; margin-right:8px; user-select:none}
  .cln.a1{color:var(--say)} .cln.a2{color:var(--amber)} .cln.a3{color:var(--think)}
  .cln.a0{color:var(--faint)}  /* unattributable: command output dumped into the channel, or an unknown self-tag */

  @media (max-width:820px){
    .stage{grid-auto-flow:column; grid-template-columns:none; grid-auto-columns:86%; overflow-x:auto; scroll-snap-type:x mandatory}
    .chan{max-height:32vh}
    .pane{scroll-snap-align:start}
    .rhead{gap:10px} .filters{margin-left:0; width:100%; order:3}
    .clock{min-width:0}
  }
  @media (prefers-reduced-motion:reduce){*{animation-duration:.001ms!important;transition-duration:.001ms!important}}
</style>

<div class="rhead">
  <a class="rhome" href="https://ctf.scratch-it.co.uk/" title="Back to The Arena"><span class="sig" aria-hidden="true"></span>The&nbsp;Arena</a>
  <h1>__ROUNDNAME__ Replay</h1>
  <span class="sub" id="rmeta"></span>
  <div class="filters" id="filters" role="group" aria-label="Filter event types">
    <span class="flabel">show</span>
    <button class="flt" data-k="prompt" aria-pressed="true"><i style="background:var(--amber)"></i>prompt</button>
    <button class="flt" data-k="think" aria-pressed="true"><i style="background:var(--think)"></i>thinking</button>
    <button class="flt" data-k="say" aria-pressed="true"><i style="background:var(--say)"></i>says</button>
    <button class="flt" data-k="run" aria-pressed="true"><i style="background:var(--run)"></i>runs</button>
    <button class="flt" data-k="out" aria-pressed="true"><i style="background:var(--dim)"></i>output</button>
  </div>
</div>

<noscript>
  <div class="noscript-note">This replay is driven by JavaScript — with it disabled the three terminals cannot
  be scrubbed or played. The written account of every round is available on
  <a href="https://ctf.scratch-it.co.uk/rounds.html">the rounds log</a>.</div>
</noscript>

<main class="stage" id="stage"></main>

<div class="chan" id="chan">
  <header><span class="csig" aria-hidden="true"></span>The channel<span class="cnote">/mnt/comms/channel.md — the one surface all three share</span></header>
  <div class="chanlog mono" id="chanlog" tabindex="0" role="region" aria-label="The shared channel, readable and writable by all three contestants"></div>
</div>

<div class="controls">
  <button class="pbtn" id="play" aria-label="Play or pause">▶</button>
  <div class="track"><input class="scrub" id="scrub" type="range" min="0" max="1000" value="0" aria-label="Scrub the battle timeline"><div class="markers" id="markers"></div></div>
  <span class="clock" id="clock"></span>
  <select class="speed" id="speed" aria-label="Playback speed">
    <option value="1">1×</option><option value="2">2×</option><option value="5" selected>5×</option><option value="10">10×</option>
  </select>
</div>

<script>
const DATA = __DATA__;
const fmt = ms => { const s=Math.floor(ms/1000); const m=Math.floor(s/60); return (m+"").padStart(2,"0")+":"+((s%60)+"").padStart(2,"0"); };
const stage = document.getElementById("stage");
const panes = {};

// A scroll box follows the newest line only while the reader is already at the bottom.
// Scroll up to read back and playback stops yanking the view; move the timeline and it re-follows.
const scrollBoxes = [];
function pinnable(el){
  el.dataset.pin = "1";
  el.addEventListener("scroll", ()=>{
    // Ignore the scroll our own auto-follow just caused. content-visibility makes
    // scrollHeight an estimate that grows as offscreen lines render, so a follow
    // scroll fires a scroll event whose apparent gap would otherwise trip this to
    // "unpinned" and the pane would stop following after a single line.
    if(el._prog){ el._prog = false; return; }
    el.dataset.pin = (el.scrollHeight - el.scrollTop - el.clientHeight < 24) ? "1" : "0";
  });
  scrollBoxes.push(el);
}
function repin(){ for(const el of scrollBoxes) el.dataset.pin = "1"; }
document.getElementById("rmeta").textContent = DATA.meta.start + " · " + Math.round(DATA.meta.dur/60000) + " min · " + DATA.meta.round;

DATA.meta.boxes.forEach((b,i)=>{
  const pane = document.createElement("div");
  pane.className = "pane c"+(i+1);
  const head = document.createElement("header");
  head.innerHTML = '<h2></h2><span class="who"></span><span class="role"></span>';
  head.querySelector("h2").textContent = b.id;
  head.querySelector(".who").textContent = b.model+" · "+b.effort+" · "+b.ip;
  head.querySelector(".role").textContent = b.role;
  const stream = document.createElement("div");
  stream.className = "stream";
  // Focusable + labelled: the pane scrolls, so keyboard users must be able to reach and scroll it.
  stream.tabIndex = 0;
  stream.setAttribute("role","region");
  stream.setAttribute("aria-label", b.id + " — terminal transcript");
  const nodes = [];
  DATA.events[b.id].forEach(ev=>{
    const el = document.createElement("div");
    el.className = "ev ev--"+ev.k;
    const ts = document.createElement("span");
    ts.className = "ts"; ts.textContent = fmt(ev.t);
    el.appendChild(ts);
    if(ev.k==="think"){ const l=document.createElement("span"); l.className="lbl"; l.textContent="thinks"; el.appendChild(l); }
    el.appendChild(document.createTextNode(ev.x));
    stream.appendChild(el);
    nodes.push({el, t:ev.t, k:ev.k, on:false});
  });
  pane.appendChild(head); pane.appendChild(stream);
  stage.appendChild(pane);
  pinnable(stream);
  panes[b.id] = {stream, nodes};
});

// shared channel — one full-width log under all three panes, coloured by author IP
const chanlog = document.getElementById("chanlog");
const chanNodes = [];
(DATA.channel||[]).forEach(c=>{
  const el=document.createElement("div"); el.className="cln";
  // Author by the writer's own tag ([ctf-2] / (ctf-3):) first, an IP mention next,
  // else unattributed — never default a line to ctf-1 just because it mentions it.
  const tag=(String(c.x).match(/[\[(]\s*ctf-([0-9])\b/)||[])[1];
  const ip=(String(c.x).match(/10\.10\.10\.(1[123])/)||[])[1];
  el.classList.add((tag==="1"||ip==="11")?"a1":(tag==="2"||ip==="12")?"a2":(tag==="3"||ip==="13")?"a3":"a0");
  const ts=document.createElement("span"); ts.className="ts"; ts.textContent=fmt(c.t); el.appendChild(ts);
  el.appendChild(document.createTextNode(c.x));
  chanlog.appendChild(el); chanNodes.push({el,t:c.t,on:false});
});
let chanLast = null;   // newest visible channel line, for auto-follow
if(!chanNodes.length) document.getElementById("chan").style.display="none";
else pinnable(chanlog);

const scrub = document.getElementById("scrub");
const clock = document.getElementById("clock");
const markersEl = document.getElementById("markers");
const playBtn = document.getElementById("play");
const speedSel = document.getElementById("speed");
const DUR = DATA.meta.dur || 1;
const filters = {prompt:true, think:true, say:true, run:true, out:true};

DATA.markers.forEach(mk=>{
  const wrap=document.createElement("div"); wrap.className="mk"; wrap.style.left=(100*mk.t/DUR)+"%";
  wrap.innerHTML='<i></i><span class="tip"></span><button aria-label="Jump to '+mk.label+'"></button>';
  wrap.querySelector(".tip").textContent=mk.label;
  wrap.querySelector("button").addEventListener("click",()=>{ pause(); seek(mk.t); });
  markersEl.appendChild(wrap);
});

let cur=0, playing=false, raf=null, last=0;

// Two strict phases. Every class mutation happens first, then every geometry read.
// Interleaving them (write, read, write, read...) forces one synchronous reflow per pane
// and is what made scrubbing cost ~175ms a frame on a 962-event round.
function applyVisibility(ms){
  for(const id in panes){
    const nodes = panes[id].nodes; let last=null;
    for(let i=0;i<nodes.length;i++){
      const n = nodes[i], show = n.t<=ms && filters[n.k];
      if(show !== n.on){ n.el.classList.toggle("on", show); n.on = show; }
      if(show) last = n.el;                 // remember the newest visible line to follow
    }
    panes[id].last = last;
  }
  let lastC=null;
  for(let i=0;i<chanNodes.length;i++){
    const n = chanNodes[i], show = n.t<=ms;
    if(show !== n.on){ n.el.classList.toggle("on", show); n.on = show; }
    if(show) lastC = n.el;
  }
  chanLast = lastC;
}
// Follow by scrolling the newest visible line itself into view — NOT by scrolling to
// scrollHeight. content-visibility:auto sizes offscreen lines from a small placeholder,
// so scrollHeight runs thousands of px short of the real bottom; "scroll to scrollHeight"
// then lands well above the newest line and falls further behind every frame (you have to
// keep scrolling down by hand). scrollIntoView resolves the node's true position and lands
// it at the bottom in one go. Only scrolls when the newest line is actually below the fold,
// so the _prog guard isn't left stale.
function stickToBottom(el, last){
  if(el.dataset.pin === "0" || !last) return;
  if(last.getBoundingClientRect().bottom <= el.getBoundingClientRect().bottom + 1) return;
  el._prog = true;
  last.scrollIntoView({block:"end", inline:"nearest"});
}

function render(ms){
  cur=ms;
  applyVisibility(ms);
  for(const id in panes) stickToBottom(panes[id].stream, panes[id].last);
  if(chanlog) stickToBottom(chanlog, chanLast);
  scrub.value = Math.round(1000*ms/DUR);
  clock.innerHTML = "<b>"+fmt(ms)+"</b> / "+fmt(DUR);
}
function seek(ms){ repin(); render(Math.max(0,Math.min(DUR,ms))); }
function pause(){ playing=false; playBtn.textContent="▶"; if(raf) cancelAnimationFrame(raf); raf=null; }
function play(){
  if(cur>=DUR) cur=0;
  playing=true; playBtn.textContent="❚❚"; last=performance.now();
  const step=now=>{
    if(!playing) return;
    const dt=now-last; last=now;
    let nx=cur + dt*(+speedSel.value);
    if(nx>=DUR){ render(DUR); pause(); return; }
    render(nx); raf=requestAnimationFrame(step);
  };
  raf=requestAnimationFrame(step);
}
playBtn.addEventListener("click",()=> playing?pause():play());
// Dragging fires input far faster than we can usefully repaint; coalesce to one render per frame.
let seekPending=null, seekRaf=null;
scrub.addEventListener("input",()=>{
  pause();
  seekPending = DUR*scrub.value/1000;
  if(seekRaf===null) seekRaf = requestAnimationFrame(()=>{ seekRaf=null; seek(seekPending); });
});
document.addEventListener("keydown",e=>{
  if(e.code==="Space"){ e.preventDefault(); playing?pause():play(); }
  else if(e.code==="ArrowRight"){ pause(); seek(cur+DUR*0.02); }
  else if(e.code==="ArrowLeft"){ pause(); seek(cur-DUR*0.02); }
});
document.querySelectorAll(".flt").forEach(btn=>{
  btn.addEventListener("click",()=>{
    const k=btn.dataset.k; filters[k]=!filters[k];
    btn.setAttribute("aria-pressed", filters[k] ? "true" : "false");
    render(cur);
  });
});
render(0);
</script>
</body>
</html>
"""


if __name__ == "__main__":
    main()
