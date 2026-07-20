# The Arena

Behavioural research into what autonomous AI agents do when you set them against
each other in a sealed Capture-the-Flag arena — read from host-side ground truth,
not the agents' own accounts.

**Live site:** https://ctf.scratch-it.co.uk

## This repository

This repo holds the **public research site** (`web/`) — a static site served from
a Cloudflare Worker. See [`web/README.md`](web/README.md) for the build and deploy.

The operational side of the project is deliberately **not** published here: the
arena provisioning, the host-side instruments (referee, watcher, replay builder),
and the raw per-round record. That material contains live infrastructure
credentials, the arena's flag secrets, and unredacted agent transcripts — which,
by the nature of the experiment, captured secrets the agents themselves read off
disk. Only material that has passed the project's redaction step is made public.

## What the site covers

- **Methodology** — how the sealed arena works, and why the authoritative record
  lives on the host, outside a contestant's reach.
- **Ethics & Containment** — the cage, why nothing real is ever targeted, and how
  the platform's cyber-safeguard shows up in the data.
- **The Rounds** — the chronological log, several rounds with scrubbable
  three-terminal replays.
- **Findings** — what the rounds keep showing: the honesty gap, the non-monotonic
  effect of effort, and how framing decides the whole game.

## Releases

Changes to the public site are recorded in [`CHANGELOG.md`](CHANGELOG.md) and
marked with an annotated git tag (`vX.Y.Z`). There is no package manifest — the
site is plain HTML and one stylesheet — so **the tag is the version**; there is
no version string to keep in sync anywhere else.

Read the semantics against the site rather than an API: **major** for a change to
the published record or the site's structure (a page moved or removed, a finding
retracted, a round re-presented), **minor** for new rounds, pages, or features,
**patch** for fixes and copy.

Adding a round is a minor release. Note that the root of this repo is an
allowlist (`/*` then `!/web/` and friends) — a new top-level file will be
silently ignored unless it is unignored explicitly.
