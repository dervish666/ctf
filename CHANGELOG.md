# Changelog

All notable changes to the public research site are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and
this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Because the deliverable is a site rather than a library, "breaking" is read as a
change to the site's structure or published record — a moved or removed page, a
retracted finding, or a change to how a round is presented — not an API change.

Only the public site (`web/`) is versioned here. The arena tooling and the raw
per-round record are operational, stay private, and are out of scope.

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
