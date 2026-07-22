#!/usr/bin/env python3
"""arena_config.py — arena-local settings (real infrastructure addresses and
seeded round secrets), loaded from a gitignored source so none of those values
live in tracked code on this public repo.

Resolution per key: environment variable ARENA_<KEY> first, then arena.local.json
sitting next to this file. A missing value returns the given default (or None),
and each caller decides whether that is fatal:

  - Infra tools (gate / orchestrate / watch_round / pull_transcripts) call
    require() — they cannot reach the arena without the real address anyway, so a
    missing value is a loud stop, not a silent wrong default.
  - Redactors (build_replay / live_redact) degrade to their GENERIC patterns and
    say so loudly: the specific host/user/password scrubs disappear, but the
    generic shapes (192.168.x, /Users/…, CTF{…}, sk-ant-…) still fire.

arena.local.json is gitignored. Copy arena.local.example.json to arena.local.json
and fill in the real values for your environment.
"""
import json
import os

_HERE = os.path.dirname(os.path.abspath(__file__))
_PATH = os.path.join(_HERE, "arena.local.json")


def _load():
    try:
        with open(_PATH) as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return {}


_CFG = _load()


def get(key, default=None):
    """Value for key, from ARENA_<KEY> env var, else arena.local.json, else default.
    Env override applies to scalar keys only (list keys come from the JSON)."""
    env = os.environ.get("ARENA_" + key.upper())
    if env is not None:
        return env
    return _CFG.get(key, default)


def require(key):
    """Like get(), but a loud stop if the value is absent — for tools that cannot
    function without the real infrastructure address."""
    v = get(key)
    if v in (None, ""):
        raise SystemExit(
            f"arena config: '{key}' is not set. Add it to {_PATH} (gitignored) or "
            f"export ARENA_{key.upper()}=… — see arena.local.example.json for the shape.")
    return v


def has_local():
    """True if an arena.local.json was found and parsed (used to warn when the
    redactors are about to run with generic patterns only)."""
    return bool(_CFG)
