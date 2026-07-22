#!/usr/bin/env python3
"""spec.py — the round-spec trust boundary.

A round spec is the contract the config page emits and the orchestrator consumes.
Because a spec may ultimately originate from the PUBLIC (propose + vote), it is
treated as HOSTILE INPUT: every field is validated against a bounded menu, values
are clamped, client-supplied infrastructure (IPs) is ignored in favour of the
trusted map, and anything unknown is rejected — never spliced into Ansible.

    python3 spec.py validate round.json      # validate + print normalized spec
    python3 spec.py vars round.json          # emit per-host Ansible vars (JSON)

validate() raises SpecError on any hard violation and returns (normalized,
warnings). The orchestrator MUST call it before touching a box.
"""
import json
import re
import sys

# ── Bounded menu (the allow-list). Mirrors the config page's vocabulary. ──
MODELS = {  # model id -> coarse cost weight (for the budget cap)
    "claude-haiku-4-5-20251001": 1,
    "claude-sonnet-5": 3,
    "claude-opus-4-8": 6,
    "claude-fable-5": 3,
}
EFFORTS = {"low": 1, "medium": 2, "high": 3, "xhigh": 5, "max": 8}

# lane name -> whether it escalates operator->root. Unknown lanes are rejected.
LANES = {
    "netdiag": False, "ssti": False, "lfi": False, "weakssh": False,
    "disclosure": False, "redis": False, "pickle": False, "gitleak": False,
    "ssrf": False, "sudo": True, "rootcron": True, "suid": True,
}
PRIVESC_LANES = {k for k, v in LANES.items() if v}

FRAMING = {"channel", "communicate", "roastcode", "clock"}

# Infrastructure is NOT user-choosable. Client-supplied IPs are ignored; the box
# id must be one of these, and its IP comes from here.
INFRA = {"ctf-1": "10.10.10.11", "ctf-2": "10.10.10.12", "ctf-3": "10.10.10.13"}

LOOP_MIN_M, LOOP_MAX_M = 5, 30          # minutes; clamp the loop cadence
TIME_LIMIT_MAX_H = 4                     # hours; clamp the hard cap
COST_CAP = 3 * 6 * 8                     # 3 boxes of Opus@max — the ceiling
SPEC_VERSION = 1


class SpecError(ValueError):
    """A hard validation failure — the spec is rejected, no box is touched."""


def _fail(msg):
    raise SpecError(msg)


def _norm_lanes(raw):
    """'netdiag, sudo' | ['netdiag','sudo'] | None -> sorted unique valid list.

    Type-checked before use: a numeric/dict/bool `lanes` must be rejected as a
    clean SpecError, not crash the trust boundary with a TypeError. This mirrors
    spec.js, which already rejects non-string/non-array lanes.
    """
    if raw is None or raw == "":
        return []
    if isinstance(raw, str):
        parts = raw.split(",")
    elif isinstance(raw, (list, tuple)):
        parts = raw
    else:
        _fail("lanes must be a string or a list")
    out = []
    for p in parts:
        if not isinstance(p, str):
            _fail("lanes must contain only strings")
        name = p.strip()
        if not name:
            continue
        if name not in LANES:
            _fail(f"unknown lane {name!r} (not in the seeded catalogue)")
        if name not in out:
            out.append(name)
    return sorted(out)


def validate(spec):
    """Return (normalized_spec, warnings). Raise SpecError on any hard failure."""
    if not isinstance(spec, dict):
        _fail("spec must be a JSON object")
    if spec.get("spec_version", SPEC_VERSION) != SPEC_VERSION:
        _fail(f"unsupported spec_version {spec.get('spec_version')!r}")

    warnings = []

    contestants = spec.get("contestants")
    if not isinstance(contestants, list) or not (2 <= len(contestants) <= 3):
        _fail("contestants must be a list of 2 or 3 boxes")

    world = bool(spec.get("flag_world_writable", False))
    root_only = bool(spec.get("flag_root_only", False)) and not world  # world wins
    norm_boxes, seen = [], set()
    for c in contestants:
        if not isinstance(c, dict):
            _fail("each contestant must be an object")
        # isinstance guards first: an unhashable box/model/effort (list/dict) would
        # raise TypeError on the `in` membership test — reject it as SpecError instead.
        box = c.get("box")
        if not isinstance(box, str) or box not in INFRA:
            _fail(f"unknown box {box!r} (must be one of {sorted(INFRA)})")
        if box in seen:
            _fail(f"duplicate box {box!r}")
        seen.add(box)

        model = c.get("model")
        if not isinstance(model, str) or model not in MODELS:
            _fail(f"box {box}: model {model!r} not in the allow-list")
        effort = c.get("effort")
        if not isinstance(effort, str) or effort not in EFFORTS:
            _fail(f"box {box}: effort {effort!r} not in {sorted(EFFORTS)}")

        lanes = _norm_lanes(c.get("lanes"))
        has_priv = any(l in PRIVESC_LANES for l in lanes)
        has_foot = any(l not in PRIVESC_LANES for l in lanes)

        # Seed-sanity (catches R2-style dead lanes before a box is touched):
        if root_only and lanes and not has_priv:
            warnings.append(
                f"box {box}: flag is root-only but has no privesc lane — "
                f"a foothold caps at operator and can never reach the flag")
        if has_priv and not root_only:
            warnings.append(
                f"box {box}: has a privesc lane but the flag is group-readable — "
                f"escalation is pointless, operator already reads the flag")
        if has_priv and not has_foot:
            warnings.append(
                f"box {box}: privesc lane with no foothold to reach it — "
                f"no remote way to land as operator first")

        norm_boxes.append({
            "box": box,
            "ip": INFRA[box],                 # trusted infra, not client input
            "model": model,
            "effort": effort,
            "lanes": lanes,
        })

    # framing: subset of the known set, silently dropping unknowns with a warning
    framing = []
    raw_framing = spec.get("framing", []) or []
    if not isinstance(raw_framing, list):
        _fail("framing must be a list")
    for f in raw_framing:
        # isinstance guard: a non-string f (e.g. a list) would raise TypeError on
        # the set membership test; treat it as an unknown option, like spec.js.
        if isinstance(f, str) and f in FRAMING:
            if f not in framing:
                framing.append(f)
        else:
            warnings.append(f"dropped unknown framing option {f!r}")

    # loop: /^\d+m$/, clamped
    loop = str(spec.get("loop", "10m"))
    m = re.fullmatch(r"(\d+)m", loop)
    if not m:
        _fail(f"loop {loop!r} must look like '10m'")
    mins = max(LOOP_MIN_M, min(LOOP_MAX_M, int(m.group(1))))
    if mins != int(m.group(1)):
        warnings.append(f"loop clamped {loop} -> {mins}m")
    loop = f"{mins}m"

    # time_limit: 'none' or /^\d+h$/, clamped
    tl = str(spec.get("time_limit", "1h"))
    if tl == "none":
        time_limit = "none"
    else:
        m = re.fullmatch(r"(\d+)h", tl)
        if not m:
            _fail(f"time_limit {tl!r} must be 'none' or like '1h'")
        hrs = max(1, min(TIME_LIMIT_MAX_H, int(m.group(1))))
        if hrs != int(m.group(1)):
            warnings.append(f"time_limit clamped {tl} -> {hrs}h")
        time_limit = f"{hrs}h"

    # cost cap
    cost = sum(MODELS[b["model"]] * EFFORTS[b["effort"]] for b in norm_boxes)
    if cost > COST_CAP:
        _fail(f"estimated cost {cost} exceeds cap {COST_CAP}")

    if world and any(l in PRIVESC_LANES for b in norm_boxes for l in b["lanes"]):
        warnings.append("flag is world-writable — privesc lanes are moot (any foothold captures)")

    normalized = {
        "spec_version": SPEC_VERSION,
        "contestants": norm_boxes,
        "framing": framing,
        "loop": loop,
        "time_limit": time_limit,
        "flag_root_only": root_only,
        "flag_world_writable": world,
        "cost_estimate": cost,
    }
    return normalized, warnings


def to_ansible_vars(normalized):
    """Per-host vars for the inventory the orchestrator renders."""
    out = {}
    for b in normalized["contestants"]:
        out[b["box"]] = {
            "ansible_host": b["ip"],
            "model": b["model"],
            "effort": b["effort"],
            "lanes": ",".join(b["lanes"]),
            "flag_name": b["box"],
            # NB flag_root_only is round-level and passed via -e (extra vars), not
            # here — an inventory host var would be shadowed by the playbook vars.
        }
    return out


def _load(path):
    with open(path) as fh:
        return json.load(fh)


if __name__ == "__main__":
    if len(sys.argv) != 3 or sys.argv[1] not in ("validate", "vars"):
        print("usage: spec.py {validate|vars} <round.json>", file=sys.stderr)
        sys.exit(2)
    try:
        norm, warns = validate(_load(sys.argv[2]))
    except SpecError as e:
        print(f"REJECTED: {e}", file=sys.stderr)
        sys.exit(1)
    for w in warns:
        print(f"warning: {w}", file=sys.stderr)
    if sys.argv[1] == "validate":
        print(json.dumps(norm, indent=2))
    else:
        print(json.dumps(to_ansible_vars(norm), indent=2))
