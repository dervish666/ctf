# Changelog

All notable changes to the public research site are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Because the deliverable is a site rather than a library, "breaking" is read as a
change to the site's structure or published record — a moved or removed page, a
retracted finding, or a change to how a round is presented — not an API change.

Only the public site (`web/`) is versioned here. The arena tooling and the raw
per-round record are operational, stay private, and are out of scope.

## [1.1.0] - 2026-07-20

The site gains its first dynamic surface: readers can now configure a round and
vote on which one runs next. Everything editorial is unchanged and still served
as static assets.

### Added

- **Round builder** (`/configure.html`) — the full round specification as a
  form: models, reasoning effort, which weaknesses are seeded on which machine,
  how reachable the flag is, the framing options, and the tempo. Each choice is
  explained in terms of what it does to the experiment rather than what it sets
  in a config file. The summary rail shows a live specification, a compute-weight
  meter, and **seed-sanity warnings** — so a board that cannot be won (a
  root-only flag with no escalation path, say) says so before a machine is
  touched.
- **The briefing, published** (`/briefing.md`, shown on the builder) — the
  `CLAUDE.md` each contestant reads, with the flag's starting path and the
  calling-card code replaced by placeholders and one real network range
  withheld. The page names all three redactions and why each was necessary.
  Readers can propose an edit to it, which is the one part of a round that is
  not a fixed menu.
- **The ballot** (`/vote.html`) — proposed rounds ranked by vote, each with a
  plain-English summary of what it would test. Says plainly what the vote does
  and does not decide, and that a clearable cookie makes the counts a signal
  rather than a poll.
- **Ballot API** (`/api/*`) — a Worker over D1. Identical dials plus an identical
  briefing edit is one variant, so a repeat proposal becomes a vote rather than a
  duplicate; identical dials with a *different* briefing edit is a new variant,
  because the briefing is what the project measures.
- **Review queue** (`/admin.html`) — token-gated, unlinked, `noindex`. Every
  proposal is held at `pending` and invisible until approved.

### Security

- Proposals are **constructed** from a bounded payload rather than accepted as a
  specification, so unknown fields cannot survive into what the orchestrator
  runs. Box identity comes from position; a client-supplied box or IP is
  discarded. `public/lib/spec.js` mirrors the controller's `spec.py` and is
  verified against it by a 3000-case differential test covering accept/reject,
  normalised output, and warning text.
- Submitted free text is withheld from every public response until a human
  approves it, and is rendered with `textContent` throughout.
- Writes require a Turnstile token, a same-origin `Origin`, and a per-IP-hash
  rate limit; the IP itself is never stored, only a salted hash. Every secret
  fails closed.

### Fixed

- The primary button and the toggle knob no longer put white on the amber
  accent, which measured **2.16:1 in dark theme** in the prototype this page
  came from. Both now use `--bg-inset`: 8.99:1 dark, 4.77:1 light.
- Form state is read from native inputs via `:has()` rather than JS-toggled
  classes, so the accessibility tree and the visible state cannot disagree.
  Radio groups are named and wrapped in labelled fieldsets, hidden inputs
  forward their focus ring to the visible card, and selection carries a
  non-colour cue.
- The human check degrades gracefully when `challenges.cloudflare.com` is
  blocked by an extension or filter: the page explains why submitting is
  disabled instead of failing silently on an uncaught error.
- **The Turnstile widget never rendered at all.** Its container was
  `<div id="turnstile">`, and an element `id` becomes a named property on
  `window` — so `window.turnstile` was the div, created by the parser before
  Cloudflare's script ran. api.js saw a truthy `window.turnstile`, logged
  "already loaded", and bailed, leaving submit permanently disabled. The
  container is now `#cf-widget`.
- **The allow-lists were checked with `in`, which walks the prototype chain.**
  `'toString' in MODELS` is true, so a model of `toString` was accepted, made
  the cost estimate `NaN`, and `NaN > COST_CAP` is false — so the compute
  ceiling silently stopped existing too. Python's `in` on a dict does not
  behave this way, which made the mirror *looser* than `spec.py`, the one thing
  it may never be. Now `Object.hasOwn`, plus a finite-cost guard, and the
  differential corpus includes prototype keys so it cannot regress.
- **An unauthenticated request could force unbounded memory allocation.** The
  body was buffered before its size was checked, and before both the Turnstile
  check and the rate limiter. It is now read against a hard byte budget that
  aborts mid-stream, so a chunked request with no declared length is bounded too.
- **`web/public/.recall/` was being deployed and served publicly** (91 KB of
  internal working notes). `.assetsignore` named `.impeccable` and nothing else;
  it now excludes dot-entries as a class, so the next tool to leave state there
  cannot leak the same way.
- Lane sub-groups in the custom board are now `role="group"` with
  `aria-labelledby`, so which weaknesses are ways *in* and which escalate to
  root is exposed programmatically, not only visually. That distinction decides
  whether a board is winnable at all.
- `[hidden]` is honoured again: an author-origin `display` (`.tally`, `.grid`)
  was overriding the UA stylesheet, so hidden containers kept rendering.

## [1.0.0] - 2026-07-20

First tagged release. Round 13 published, and a full accessibility and
performance pass over the site and the replay instrument.

### Added

- **Round 13** — "Give them a clock and they play a different game", with a
  scrubbable three-terminal replay.
- **Skip link** on every page, as the first tab stop, targeting `main`.
- **Theme persistence** — the light/dark choice now survives navigation, read by
  a blocking script in `<head>` so the stored theme never flashes the wrong one.
- **Keyboard access to the replay transcripts** — the three terminal panes and
  the shared channel are now labelled, focusable regions. Previously the entire
  contents of a replay were unreachable without a mouse.
- **`<noscript>` fallback** in replays, pointing at the written round log.
- **`color-scheme`** declaration, so native scrollbars and form controls follow
  the active theme.

### Fixed

- **Contrast now meets WCAG AA across the whole site**, in both themes, verified
  against the composited backgrounds elements actually sit on — including hover
  and open states, where every real failure was hiding. Eight tokens moved; the
  worst case was 2.68:1.
- **Replay panes never followed the action.** `scroll-behavior: smooth` on a
  container whose `scrollTop` is re-targeted every frame restarts the animation
  before it can advance, so the panes never scrolled at all. Only readers with
  reduced motion enabled ever saw this work.
- **Replay scrubbing was unusably slow** — interleaved DOM writes and geometry
  reads forced a synchronous reflow per pane, costing ~175 ms per frame on a
  962-event round. Now ~9 ms.
- **The round count said twelve** on the home page and the ethics page while the
  ledger held thirteen.
- **Heading hierarchy** — four pages jumped from `h1` to `h3`, and the round
  ledger had no headings at all, leaving its thirteen entries invisible to
  heading navigation.
- **Marker tooltips** in the replay timeline appeared on hover only, never on
  keyboard focus.

### Changed

- **Touch targets** raised to 44 px via transparent hit-area expansion, so the
  visual design is unchanged. The replay's scrub track went from a 4 px to a
  24 px grab area.
- **Corner radii consolidated** onto the documented 3 / 5 / 7 px scale, removing
  the drift to 4 px and 6 px.
- Round titles are now `h2` elements rather than styled spans.
- Replay event lines use `content-visibility` to skip layout for offscreen
  content.

---

Work before 1.0.0 was untagged: the initial site, the 404 page, and the rounds,
findings and stack pages all landed on 2026-07-19. See `git log` for detail.
