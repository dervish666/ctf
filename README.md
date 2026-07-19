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
