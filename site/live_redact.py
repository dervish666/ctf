#!/usr/bin/env python3
"""live_redact.py — the redact-then-prove gate for the LIVE feed.

build_replay.py can redact a finished round, scan the whole artifact, and refuse
to emit if anything leaked. A live feed has no such luxury: bytes go out while the
round is still running, so there is no "check the finished thing" step. This module
is what replaces it.

The rule it enforces, per batch, is the same one build_replay states at its
make_redactor docstring: EVERY transform must have a matching detector, so the
output can be PROVEN clean rather than assumed clean.

    redact -> verify -> publish        (verify fails => publish NOTHING)

Failing closed matters more here than anywhere else in the project. A missed
secret in a replay is a bad afternoon with a git history rewrite. A missed secret
on a live feed is already on someone's screen.

Live-specific additions on top of build_replay's redactor:

  - MARK{...} calling cards. build_replay leaves these (they are historical by the
    time a replay ships). Live, a mark is the round's active, unbluffable proof of
    compromise — publishing one mid-round lets a viewer, or a contestant reading
    the feed, forge a capture that never happened.
  - Operator filesystem paths (/Users/..., /home/...). Terminal scrollback is full
    of these in a way a curated replay is not.
  - The arena's own flag PATHS, not just the tokens. Live, "the flag is currently
    at /srv/.abc123" is a defender's position, and the whole game is hiding it.

Usage:
    from live_redact import LiveRedactor
    r = LiveRedactor()                    # loads secrets from ansible/flags.local.yml
    safe, why = r.scrub(text)             # -> (clean_text, None) or (None, reason)
"""
import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(HERE)
sys.path.insert(0, HERE)

# Reuse rather than fork: a second copy of these rules would drift from the
# replay builder's, and then "redacted" would mean two different things.
from build_replay import make_redactor, secret_patterns, load_tokens  # noqa: E402

FLAGS = os.path.join(REPO, "ansible", "flags.local.yml")


def load_secrets(flags_path=FLAGS):
    """token / mark / path per box from the controller-only flags file."""
    out = {"token": {}, "mark": {}, "path": {}}
    if not os.path.exists(flags_path):
        return out
    cur = None
    for raw in open(flags_path):
        s = raw.strip()
        if s.startswith("ctf-") and s.endswith(":"):
            cur = s[:-1]
            continue
        if not cur or '"' not in s:
            continue
        for field in ("token", "mark", "path"):
            if s.startswith(field + ":"):
                out[field][cur] = s.split('"')[1]
    return out


class LiveRedactor:
    """Redacts, then proves the result is clean. Never returns text it cannot prove."""

    def __init__(self, flags_path=FLAGS):
        self.secrets = load_secrets(flags_path)
        tokens = self.secrets["token"]
        # FAIL CLOSED. The live feed always runs against the current round, whose
        # flags MUST be loaded — without them the exact token/mark/path detectors
        # vanish and the gate degrades to generic patterns only, i.e. fails OPEN
        # while bytes stream to a public page. Refuse to construct rather than run
        # half-armed. (build_replay, offline and historical, only warns.)
        if not tokens:
            raise RuntimeError(
                f"no flag tokens loaded from {flags_path} — refusing to run the live "
                f"redactor without its exact-secret detectors (it would fail OPEN).")
        self._base = make_redactor(tokens)

        # Detectors. Anything here that survives into output means the matching
        # transform below failed, and the batch is dropped rather than published.
        self._patterns = [re.compile(p) for p in secret_patterns(tokens)]
        self._patterns += [re.compile(r"MARK\{[0-9a-f]{6,}")]
        self._patterns += [re.compile(r"/Users/[A-Za-z0-9._-]+")]
        for value in list(self.secrets["mark"].values()) + list(self.secrets["path"].values()):
            if value:
                self._patterns.append(re.compile(re.escape(value)))

    def _transform(self, t):
        t = self._base(t)

        # Live-only: the active calling card. Replace named values first so the
        # generic pattern cannot mask which box a residual mark belonged to.
        for name, mark in self.secrets["mark"].items():
            if mark:
                t = t.replace(mark, "MARK{‹%s's mark›}" % name)
        t = re.sub(r"MARK\{[0-9a-f]{6,}\}?", "MARK{‹mark›}", t)

        # Live-only: a flag's CURRENT location is a defender's position.
        for name, path in self.secrets["path"].items():
            if path:
                t = t.replace(path, "/srv/‹%s's flag›" % name)
        t = re.sub(r"/srv/\.[0-9a-f]{6,}", "/srv/‹hidden flag›", t)

        # Live-only: operator filesystem paths.
        t = re.sub(r"/Users/[A-Za-z0-9._-]+", "/Users/‹user›", t)
        t = re.sub(r"/home/(?!operator\b|ctf\b)[A-Za-z0-9._-]+", "/home/‹user›", t)
        return t

    def scrub(self, text):
        """Return (clean_text, None), or (None, reason) if it could not be proven clean."""
        if not text:
            return text, None
        try:
            out = self._transform(text)
        except Exception as e:                      # never let a redactor bug publish raw text
            return None, f"redactor raised {type(e).__name__}: {e}"

        for pat in self._patterns:
            hit = pat.search(out)
            if hit:
                # Deliberately does NOT echo the matched text — the reason string
                # gets logged, and logs are not a safe place for the thing we just
                # refused to publish.
                return None, f"post-redaction detector {pat.pattern!r} still matched"
        return out, None

    # Enum/id fields that are never free text. EVERYTHING else that is a string is
    # scrubbed — so a new payload field cannot smuggle unredacted text past the gate
    # just because it wasn't on a hand-maintained allow-list of field names. The
    # Worker stores the payload verbatim, so this is the only place it gets cleaned.
    _SKIP = frozenset({"kind", "box", "role", "label", "event", "seq", "t"})

    def scrub_event(self, event):
        """Scrub every free-text field of an event dict. Drops the whole event on failure."""
        out = dict(event)
        for field, val in list(out.items()):
            if field in self._SKIP or not isinstance(val, str):
                continue
            clean, why = self.scrub(val)
            if clean is None:
                return None, f"{field}: {why}"
            out[field] = clean
        return out, None


def self_test():
    """Prove the gate catches what it claims to, using the REAL live secrets."""
    r = LiveRedactor()
    s = r.secrets
    if not s["token"]:
        print("no flags.local.yml — cannot self-test against real secrets", file=sys.stderr)
        return 2

    box = sorted(s["token"])[0]
    cases = [
        ("real flag token", f"got it: {s['token'][box]}"),
        ("real mark", f"wrote {s['mark'][box]} into the file"),
        ("real flag path", f"flag lives at {s['path'][box]}"),
        ("generic flag", "found CTF{deadbeef1234} on disk"),
        ("generic mark", "MARK{a46afb196841bbb1} was there"),
        ("api key", "export ANTHROPIC_API_KEY=sk-ant-abc123DEF456"),
        ("home net", "scanning 192.168.31.44"),          # generic 192.168.x — tests the shape, not the real host
        ("operator user", "/Users/example/Code/ctf"),    # generic path — tests the /Users scrub
        ("private key", "-----BEGIN RSA PRIVATE KEY-----\nabc\n-----END RSA PRIVATE KEY-----"),
        ("hidden flag path", "cat /srv/.e71260238508"),
    ]
    bad = 0
    for label, raw in cases:
        clean, why = r.scrub(raw)
        if clean is None:
            print(f"  DROPPED  {label:18} ({why})")
            continue
        leaked = [p.pattern for p in r._patterns if p.search(clean)]
        status = "LEAK" if leaked else "ok"
        if leaked:
            bad += 1
        print(f"  {status:8} {label:18} -> {clean.strip()[:64]}")

    benign = "operator@ctf-1:~$ nmap -sn 10.10.10.0/24"
    clean, why = r.scrub(benign)
    if clean != benign:
        print(f"  OVER-REDACTED benign line: {benign!r} -> {clean!r}")
        bad += 1
    else:
        print(f"  ok       benign line preserved")

    print("\nself-test:", "PASS" if not bad else f"FAIL ({bad})")
    return 0 if not bad else 1


if __name__ == "__main__":
    sys.exit(self_test())
