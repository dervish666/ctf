-- The Arena — ballot storage (Cloudflare D1 / SQLite).
--
--   npx wrangler d1 create ctf-arena-ballot
--   npx wrangler d1 execute ctf-arena-ballot --remote --file=./schema.sql
--
-- Public input reaches this schema, so the integrity rules live here rather than
-- only in application code: a variant is unique by spec_hash, and a voter votes
-- once per variant by primary key. Both are enforced by the database, so a race
-- between two Workers cannot produce a duplicate.

-- ── Variants ──────────────────────────────────────────────────────────────
-- One row per distinct proposed round. "Distinct" means the canonical spec AND
-- the proposed briefing edit together: the same dials with a different briefing
-- is a different experiment, so it is a different variant.
CREATE TABLE IF NOT EXISTS variants (
  id              INTEGER PRIMARY KEY AUTOINCREMENT,
  spec_hash       TEXT    NOT NULL UNIQUE,  -- sha256(canonical spec + briefing patch)
  options_hash    TEXT    NOT NULL,         -- sha256(canonical spec only) — for "same dials, different briefing"
  spec_json       TEXT    NOT NULL,         -- the normalized spec, as spec.py would emit it
  title           TEXT    NOT NULL,         -- derived label, e.g. "Opus ×3 · chains · clock"
  claude_md_patch TEXT,                     -- NULL, or the proposed briefing (free text — untrusted)
  rationale       TEXT,                     -- NULL, or "why run this" (free text — untrusted)
  status          TEXT    NOT NULL DEFAULT 'pending'
                          CHECK (status IN ('pending','approved','rejected','scheduled','ran')),
  round_no        INTEGER,                  -- set when this variant actually ran
  review_note     TEXT,
  reviewed_at     INTEGER,
  created_at      INTEGER NOT NULL,
  submitter_id    TEXT    NOT NULL,         -- the submitter's voter id (opaque; lets them find their own)
  vote_count      INTEGER NOT NULL DEFAULT 0
);

-- The ballot's only hot query: approved variants, most-voted first, oldest wins ties.
CREATE INDEX IF NOT EXISTS idx_variants_rank
  ON variants (status, vote_count DESC, created_at ASC);

-- "Same dials, different briefing" lookups on submit.
CREATE INDEX IF NOT EXISTS idx_variants_options ON variants (options_hash);

-- ── Votes ─────────────────────────────────────────────────────────────────
-- The composite primary key IS the one-vote-per-voter rule. Votes are
-- retractable, so the UI can offer a toggle rather than a one-way commitment.
CREATE TABLE IF NOT EXISTS votes (
  variant_id INTEGER NOT NULL REFERENCES variants(id) ON DELETE CASCADE,
  voter_id   TEXT    NOT NULL,
  created_at INTEGER NOT NULL,
  PRIMARY KEY (variant_id, voter_id)
);

-- Lets a returning voter's ballot render with their own votes marked, in one query.
CREATE INDEX IF NOT EXISTS idx_votes_voter ON votes (voter_id);

-- vote_count is denormalised so ranking never counts rows. Keep it honest in the
-- database, not in the Worker — application code forgets, triggers do not.
CREATE TRIGGER IF NOT EXISTS votes_after_insert AFTER INSERT ON votes BEGIN
  UPDATE variants SET vote_count = vote_count + 1 WHERE id = NEW.variant_id;
END;

CREATE TRIGGER IF NOT EXISTS votes_after_delete AFTER DELETE ON votes BEGIN
  UPDATE variants SET vote_count = vote_count - 1 WHERE id = OLD.variant_id;
END;

-- ── Rate limiting ─────────────────────────────────────────────────────────
-- Fixed-window counters keyed by action + hashed IP + window. The IP is never
-- stored — only a salted hash of it, which is enough to count and useless after.
CREATE TABLE IF NOT EXISTS rate_buckets (
  bucket     TEXT    PRIMARY KEY,  -- "<action>:<ip_hash>:<window>"
  n          INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_rate_expiry ON rate_buckets (expires_at);
