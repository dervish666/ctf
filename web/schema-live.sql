-- The Arena — live round feed (Cloudflare D1).
--
--   npx wrangler d1 execute ctf-arena-ballot --remote --file=./schema-live.sql
--
-- A round produces roughly 500 events in an hour. That rate is why this is a
-- table polled with a cursor rather than a Durable Object fanning out sockets:
-- viewers poll faster than the arena generates data, so a push transport would
-- be machinery in service of nothing.

-- ── The feed ──────────────────────────────────────────────────────────────
-- `seq` is the cursor. Viewers hold the last seq they saw and ask for what came
-- after it, so a reader that tabs away and returns catches up rather than
-- resyncing from scratch.
CREATE TABLE IF NOT EXISTS live_events (
  seq        INTEGER PRIMARY KEY AUTOINCREMENT,
  round_id   TEXT    NOT NULL,
  t          INTEGER NOT NULL,   -- arena wall-clock ms, from the runtime, not guessed
  kind       TEXT    NOT NULL
             CHECK (kind IN ('stream','truth','channel','status','note')),
  box        TEXT,               -- ctf-1/2/3, or NULL for round-level events
  payload    TEXT    NOT NULL,   -- JSON; every free-text field already redacted+proven
  created_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_live_cursor ON live_events (round_id, seq);

-- ── Round state ───────────────────────────────────────────────────────────
-- Single row. `status` is what the public page keys off, and 'killed' is the
-- state the kill switch lands in — deliberately distinct from 'ended', because
-- a feed that was stopped on purpose should not read as a round that finished.
CREATE TABLE IF NOT EXISTS live_state (
  id         INTEGER PRIMARY KEY CHECK (id = 1),
  round_id   TEXT,
  title      TEXT,
  status     TEXT    NOT NULL DEFAULT 'idle'
             CHECK (status IN ('idle','live','ended','killed')),
  started_at INTEGER,
  ends_at    INTEGER,            -- when the clock runs out, for the countdown
  delay_ms   INTEGER NOT NULL DEFAULT 90000,
  note       TEXT,               -- shown on the page; how a kill explains itself
  updated_at INTEGER NOT NULL
);

INSERT OR IGNORE INTO live_state (id, status, updated_at) VALUES (1, 'idle', 0);
