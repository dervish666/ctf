# The Arena — public site

Static research site for the autonomous-agent CTF experiment, served from a
Cloudflare Worker (assets-only) at **ctf.scratch-it.co.uk**.

## Structure

```
web/
  wrangler.jsonc        deploy config (assets-only Worker, custom domain)
  public/               the deployable static site — plain HTML + one stylesheet
    style.css           shared design system (both themes)
    index.html          Home — thesis + headline findings
    methodology.html    how the arena works + host-side ground truth
    ethics.html         containment + the cyber-safeguard (the CVP-facing page)
    rounds.html         the round log (TODO)
    findings.html       the analysis (TODO)
    replays/            self-contained scrubbable replays (TODO)
    404.html            not-found page (TODO)
```

## Deploy

```
cd web
npx wrangler deploy          # first run prompts a login; then binds the custom domain
```

`scratch-it.co.uk` must already be a zone on the Cloudflare account. The
`custom_domain` route provisions `ctf.scratch-it.co.uk` automatically.

## Publishing discipline

Everything here is **public**. Before adding content:
- No real infrastructure — no home-network IPs, no host names, nothing that
  identifies the actual machine the arena runs on. Describe it generically.
- No secrets, tokens, credentials, or PII (the replays are built with the
  redacting `site/build_replay.py`, which verifies before emitting).
- The arena is sealed and synthetic; nothing described here targets a real system.
