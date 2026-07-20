# The Arena — public site

Static research site for the autonomous-agent CTF experiment, served from a
Cloudflare Worker at **ctf.scratch-it.co.uk**, plus a small API for the round
ballot.

## Structure

```
web/
  wrangler.jsonc        deploy config (Worker + static assets + D1)
  schema.sql            D1 schema for the ballot
  src/
    index.js            the /api/* Worker — the ONLY dynamic surface
  public/               the deployable static site
    style.css           shared design system (both themes)
    lib/spec.js         the round-spec validator (see "One validator", below)
    index.html          Home — thesis + headline findings
    methodology.html    how the arena works + host-side ground truth
    ethics.html         containment + the cyber-safeguard
    rounds.html         the round log
    findings.html       the analysis
    stack.html          what the arena is built from
    configure.html      the round builder — emits a spec, submits to the ballot
    vote.html           the ranked ballot
    admin.html          review queue (unlinked, noindex, token-gated)
    briefing.md         the published agent briefing, redacted
    replays/            self-contained scrubbable replays
    404.html            not-found page
```

The editorial pages are unchanged by the ballot: `run_worker_first` is scoped to
`/api/*`, so every other path is still served straight from `./public` with no
Worker invocation.

## One validator, two runtimes

`public/lib/spec.js` is imported by **both** the Worker (`src/index.js`) and the
browser (`configure.html`). The builder's live warnings and the server's
authoritative ones are therefore the same code, and cannot drift.

It mirrors the controller's `spec.py`, which calls itself "the round-spec trust
boundary" and treats a spec as hostile input precisely because it may originate
from the public. The rule for that mirror is one-directional:

> **It may be stricter than `spec.py`. It may never be looser.**

A spec accepted by the public path but rejected by the controller is a broken
promise to whoever proposed it. A differential test over 3000 generated specs
confirms parity on accept/reject, normalised output, and warning text.

Two deliberate tightenings: the Worker **constructs** the spec from a bounded
payload rather than accepting one (so unknown keys cannot ride along), and box
identity comes from position, never from the request. Infrastructure addresses
appear nowhere in this directory; `spec.py` injects them at provisioning time.

## Deploy

```
cd web
npx wrangler deploy
```

`scratch-it.co.uk` must already be a zone on the Cloudflare account.

### First-time ballot setup

1. **Create the database** (already done once; the id is in `wrangler.jsonc`):
   ```
   npx wrangler d1 create ctf-arena-ballot
   npx wrangler d1 execute ctf-arena-ballot --remote --file=./schema.sql
   ```

2. **Create a Turnstile widget** in the Cloudflare dashboard (Turnstile → Add
   widget, hostname `ctf.scratch-it.co.uk`). Put the **site key** in
   `wrangler.jsonc` under `vars.TURNSTILE_SITE_KEY` — it is public by design and
   rendered into the page.

3. **Set the three secrets:**
   ```
   npx wrangler secret put BALLOT_SECRET     # long random string; signs the voter cookie, salts the IP hash
   npx wrangler secret put TURNSTILE_SECRET  # the widget's secret key
   npx wrangler secret put ADMIN_TOKEN       # long random string; gates the review queue
   ```

   All three **fail closed**. Without `BALLOT_SECRET` the API refuses to serve at
   all; without `TURNSTILE_SECRET` writes are rejected with a message saying so;
   without `ADMIN_TOKEN` the review queue is unreachable. A missing secret can
   never silently disable a control.

### Local development

```
cp /dev/null .dev.vars     # gitignored
# BALLOT_SECRET=anything
# TURNSTILE_SECRET=1x0000000000000000000000000000000AA   <- Cloudflare's always-passes test key
# ADMIN_TOKEN=anything
npx wrangler d1 execute ctf-arena-ballot --local --file=./schema.sql
npx wrangler dev --local
```

Turnstile's published test keys are site `1x00000000000000000000AA` / secret
`1x0000000000000000000000000000000AA`. **Never deploy with those** — they accept
everything.

## Running a voted round

```
curl https://ctf.scratch-it.co.uk/api/variants/<id>/spec > round.json
python3 spec.py validate round.json      # the controller re-validates independently
./orchestrate.py plan round.json
```

The public path never touches a machine. It produces a specification; the
controller validates it again from scratch and a human runs it.

## Moderation

Every proposal enters at `status='pending'` and is invisible on the ballot until
approved through `/admin.html`. The Worker withholds submitted free text from
every public response until that point, and the pages render all submitter text
with `textContent`, never `innerHTML` — two independent guards, so neither is
load-bearing alone.

## Publishing discipline

Everything in `public/` is public. Before adding content:
- No real infrastructure — no home-network IPs, no host names, nothing that
  identifies the actual machine the arena runs on.
- No secrets, tokens, credentials, or PII. The replays are built with the
  redacting `site/build_replay.py`, which verifies before emitting.
- `briefing.md` is the agent briefing with the flag path and calling-card code
  replaced by placeholders and one real network range withheld. The page says
  which three things changed and why; the omissions are stated rather than
  hidden.
- The arena is sealed and synthetic; nothing described here targets a real system.
