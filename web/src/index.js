/**
 * The Arena — ballot API.
 *
 * The site is otherwise static; this Worker exists only for /api/*, which
 * `run_worker_first` in wrangler.jsonc routes here. Every other path is served
 * straight from ./public as before, so the editorial site keeps its old
 * behaviour exactly.
 *
 * Everything below runs on public input. The posture:
 *   - the spec is CONSTRUCTED from a bounded payload, never accepted as a blob
 *     (see spec.js — it may be stricter than spec.py, never looser)
 *   - free text (briefing edit, rationale) is stored raw and NEVER interpolated
 *     into HTML by this Worker; it leaves as JSON and the page renders it with
 *     textContent, so there is no injection path through the DOM
 *   - free text is held at status='pending' until a human approves it, so
 *     nothing unreviewed is ever served to a reader
 *   - writes require a Turnstile token, a same-origin Origin, and survive a
 *     per-IP-hash rate limit; identity is a signed cookie, not a claim
 */

// The validator lives under ./public so the BROWSER can import the same file the
// Worker does. The builder's live warnings and the server's authoritative ones
// are then the same code by construction, and cannot drift apart.
import { buildSpec, hashes, deriveTitle, SpecError, COST_CAP, MODELS, EFFORTS, LANES, FRAMING, BOXES } from '../public/lib/spec.js';

const MAX_BODY = 24 * 1024;      // bytes; a briefing edit is prose, not a payload
const MAX_PATCH = 8000;          // chars of proposed briefing
const MAX_RATIONALE = 600;       // chars of "why run this"
const COOKIE = 'arena_voter';
const COOKIE_MAX_AGE = 60 * 60 * 24 * 365;
const BALLOT_LIMIT = 200;

const RATE = {
  propose: { limit: 5, windowSec: 3600 },
  vote: { limit: 40, windowSec: 3600 },
};

// ── small helpers ─────────────────────────────────────────────────────────

const json = (body, status = 200, headers = {}) => new Response(JSON.stringify(body), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...headers },
});

const bad = (message, status = 400, extra = {}) => json({ error: message, ...extra }, status);

const enc = new TextEncoder();
const toHex = (buf) => [...new Uint8Array(buf)].map((b) => b.toString(16).padStart(2, '0')).join('');

async function hmacHex(secret, message) {
  const key = await crypto.subtle.importKey('raw', enc.encode(secret), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return toHex(await crypto.subtle.sign('HMAC', key, enc.encode(message)));
}

/** Constant-time compare, so a token check cannot be walked byte by byte. */
function timingSafeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string' || a.length !== b.length) return false;
  let diff = 0;
  for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
  return diff === 0;
}

function readCookie(request, name) {
  const header = request.headers.get('cookie');
  if (!header) return null;
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq < 0) continue;
    if (part.slice(0, eq).trim() === name) return part.slice(eq + 1).trim();
  }
  return null;
}

/**
 * Voter identity: a random id plus an HMAC of it. The signature stops someone
 * inventing ids to stuff the ballot; it does not stop them clearing the cookie,
 * which is why the ballot page says out loud that counts are a signal, not a poll.
 */
async function readVoter(request, env) {
  const raw = readCookie(request, COOKIE);
  if (!raw) return null;
  const dot = raw.lastIndexOf('.');
  if (dot < 1) return null;
  const id = raw.slice(0, dot);
  const sig = raw.slice(dot + 1);
  if (!/^[0-9a-f-]{36}$/.test(id)) return null;
  const expected = await hmacHex(env.BALLOT_SECRET, `voter:${id}`);
  return timingSafeEqual(sig, expected) ? id : null;
}

async function mintVoter(env) {
  const id = crypto.randomUUID();
  const sig = await hmacHex(env.BALLOT_SECRET, `voter:${id}`);
  return { id, cookie: `${COOKIE}=${id}.${sig}; Path=/; Max-Age=${COOKIE_MAX_AGE}; HttpOnly; Secure; SameSite=Lax` };
}

/** The IP is hashed with a server secret and never stored raw — enough to count, useless after. */
async function ipHash(request, env) {
  const ip = request.headers.get('cf-connecting-ip') || 'unknown';
  return (await hmacHex(env.BALLOT_SECRET, `ip:${ip}`)).slice(0, 32);
}

/**
 * Fixed-window rate limit. Not distributed-perfect — two simultaneous requests
 * can both read the same count — but the window is an hour and the cost of an
 * occasional extra vote is nil, so the simple version is the right one.
 */
async function rateLimit(env, action, who) {
  const { limit, windowSec } = RATE[action];
  const now = Math.floor(Date.now() / 1000);
  const window = Math.floor(now / windowSec);
  const bucket = `${action}:${who}:${window}`;
  const expiresAt = (window + 1) * windowSec;

  await env.DB.prepare(
    'INSERT INTO rate_buckets (bucket, n, expires_at) VALUES (?, 1, ?) '
    + 'ON CONFLICT(bucket) DO UPDATE SET n = n + 1',
  ).bind(bucket, expiresAt).run();

  const row = await env.DB.prepare('SELECT n FROM rate_buckets WHERE bucket = ?').bind(bucket).first();
  if (Math.random() < 0.02) {
    // Opportunistic sweep: cheap, and stops the table growing without bound.
    await env.DB.prepare('DELETE FROM rate_buckets WHERE expires_at < ?').bind(now).run();
  }
  return { ok: (row?.n ?? 1) <= limit, retryAfter: expiresAt - now };
}

/** Cross-origin writes are rejected outright; SameSite=Lax is the belt, this is the braces. */
function sameOrigin(request) {
  const origin = request.headers.get('origin');
  if (!origin) return true; // non-CORS clients (curl) send none; the Turnstile check still applies
  try {
    return new URL(origin).host === new URL(request.url).host;
  } catch {
    return false;
  }
}

async function verifyTurnstile(env, token, request) {
  if (!env.TURNSTILE_SECRET) {
    // Fail closed and say why. A missing secret must never silently disable the
    // only bot control on a public write path.
    return { ok: false, reason: 'ballot is not configured for submissions (missing Turnstile secret)', status: 503 };
  }
  if (typeof token !== 'string' || !token || token.length > 2048) {
    return { ok: false, reason: 'human check missing — reload the page and try again', status: 400 };
  }
  const body = new FormData();
  body.append('secret', env.TURNSTILE_SECRET);
  body.append('response', token);
  const ip = request.headers.get('cf-connecting-ip');
  if (ip) body.append('remoteip', ip);

  let result;
  try {
    const res = await fetch('https://challenges.cloudflare.com/turnstile/v0/siteverify', { method: 'POST', body });
    result = await res.json();
  } catch (e) {
    console.error('turnstile: verification request failed —', e.message);
    return { ok: false, reason: 'human check could not be verified — try again shortly', status: 502 };
  }
  if (!result.success) {
    console.warn('turnstile: rejected —', JSON.stringify(result['error-codes'] || []));
    return { ok: false, reason: 'human check failed — reload the page and try again', status: 403 };
  }
  return { ok: true };
}

function isAdmin(request, env) {
  if (!env.ADMIN_TOKEN) return false;
  const header = request.headers.get('authorization') || '';
  const prefix = 'Bearer ';
  if (!header.startsWith(prefix)) return false;
  return timingSafeEqual(header.slice(prefix.length), env.ADMIN_TOKEN);
}

/**
 * Read the body with a hard byte budget, aborting as soon as it is exceeded.
 *
 * `await request.text()` buffers the whole body first and checks the size after,
 * which is too late — the memory is already committed. That matters here because
 * readJson runs BEFORE the Turnstile check and before the rate limiter, so an
 * anonymous client could otherwise post an enormous body for free, uncounted, and
 * repeatedly. A Content-Length check alone is not enough: a chunked request
 * declares no length, so the budget has to be enforced against the stream itself.
 */
async function readBounded(request) {
  if (!request.body) return '';
  const reader = request.body.getReader();
  const chunks = [];
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > MAX_BODY) {
        await reader.cancel('body too large');
        throw new SpecError('request body too large');
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
  }
  const joined = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) { joined.set(chunk, offset); offset += chunk.byteLength; }
  return new TextDecoder().decode(joined);
}

async function readJson(request) {
  const type = request.headers.get('content-type') || '';
  if (!type.includes('application/json')) throw new SpecError('expected application/json');

  // Refuse on the declared length BEFORE reading anything.
  const declared = Number(request.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_BODY) throw new SpecError('request body too large');

  const text = await readBounded(request);
  try {
    return JSON.parse(text);
  } catch {
    throw new SpecError('body is not valid JSON');
  }
}

/**
 * A variant as the public sees it. Free text is included only once approved —
 * `status` gates it here, at the single point where rows become responses, rather
 * than at each call site where it would eventually be forgotten.
 */
function publicVariant(row, myVotes) {
  const approved = row.status === 'approved' || row.status === 'scheduled' || row.status === 'ran';
  return {
    id: row.id,
    title: row.title,
    spec: JSON.parse(row.spec_json),
    votes: row.vote_count,
    status: row.status,
    round_no: row.round_no,
    created_at: row.created_at,
    voted: myVotes ? myVotes.has(row.id) : false,
    claude_md_patch: approved ? row.claude_md_patch : null,
    rationale: approved ? row.rationale : null,
    has_briefing_edit: Boolean(row.claude_md_patch),
  };
}

// ── handlers ──────────────────────────────────────────────────────────────

/** The menu the builder renders, served from the validator so the two cannot drift. */
function handleMenu(env) {
  return json({
    spec_version: 1,
    boxes: BOXES,
    models: MODELS,
    efforts: EFFORTS,
    lanes: LANES,
    framing: FRAMING,
    cost_cap: COST_CAP,
    turnstile_site_key: env.TURNSTILE_SITE_KEY || null,
    submissions_open: Boolean(env.TURNSTILE_SECRET),
  });
}

async function handleBallot(request, env, voterId) {
  const url = new URL(request.url);
  const includeAll = url.searchParams.get('all') === '1' && isAdmin(request, env);

  const statusFilter = includeAll
    ? "status IN ('pending','approved','rejected','scheduled','ran')"
    : "status IN ('approved','scheduled','ran')";

  const { results } = await env.DB.prepare(
    `SELECT * FROM variants WHERE ${statusFilter} ORDER BY vote_count DESC, created_at ASC LIMIT ?`,
  ).bind(BALLOT_LIMIT).all();

  let myVotes = new Set();
  if (voterId) {
    const mine = await env.DB.prepare('SELECT variant_id FROM votes WHERE voter_id = ?').bind(voterId).all();
    myVotes = new Set(mine.results.map((r) => r.variant_id));
  }

  return json({
    variants: results.map((r) => publicVariant(r, myVotes)),
    turnstile_site_key: env.TURNSTILE_SITE_KEY || null,
    submissions_open: Boolean(env.TURNSTILE_SECRET),
    admin: includeAll,
  });
}

/**
 * Propose a round.
 *
 * Identical dials AND identical briefing edit = the same variant, so the vote
 * lands on the existing row instead of splitting the ballot. Identical dials with
 * a DIFFERENT briefing edit is a new variant, because the briefing is precisely
 * the thing the experiment measures — but we tell the submitter what it collided
 * with so it does not look like the dedupe failed.
 */
async function handlePropose(request, env, voterId) {
  const payload = await readJson(request);

  const turnstile = await verifyTurnstile(env, payload.turnstile_token, request);
  if (!turnstile.ok) return bad(turnstile.reason, turnstile.status);

  const limited = await rateLimit(env, 'propose', await ipHash(request, env));
  if (!limited.ok) {
    return bad(`too many proposals from here — try again in ${Math.ceil(limited.retryAfter / 60)} minutes.`, 429);
  }

  const { normalized, warnings } = buildSpec(payload);

  let patch = typeof payload.claude_md_patch === 'string' ? payload.claude_md_patch : '';
  if (patch.length > MAX_PATCH) return bad(`the briefing edit is longer than ${MAX_PATCH} characters`);
  let rationale = typeof payload.rationale === 'string' ? payload.rationale.trim() : '';
  if (rationale.length > MAX_RATIONALE) return bad(`the note is longer than ${MAX_RATIONALE} characters`);

  const { optionsHash, specHash, cleanPatch } = await hashes(normalized, patch);
  patch = cleanPatch;

  const existing = await env.DB.prepare('SELECT * FROM variants WHERE spec_hash = ?').bind(specHash).first();
  if (existing) {
    // What "already exists" means depends on what happened to it. Casting a vote
    // on every match would attach votes to rows that are not on the ballot and
    // never will be, while telling the submitter their vote had counted.
    if (existing.status === 'rejected') {
      return json({
        outcome: 'rejected',
        variant: { id: existing.id, title: existing.title, status: 'rejected' },
        review_note: existing.review_note,
        warnings,
      }, 409);
    }
    if (existing.status === 'ran') {
      return json({
        outcome: 'ran',
        variant: { id: existing.id, title: existing.title, status: 'ran', round_no: existing.round_no },
        warnings,
      }, 409);
    }

    const voteResult = await castVote(env, existing.id, voterId, true);
    return json({
      outcome: 'existing',
      variant: publicVariant({ ...existing, vote_count: existing.vote_count + (voteResult.added ? 1 : 0) }, new Set([existing.id])),
      pending_review: existing.status === 'pending',
      already_voted: !voteResult.added,
      warnings,
    });
  }

  // Same dials, different briefing — worth naming, or the dedupe looks broken.
  const sibling = patch
    ? await env.DB.prepare(
      "SELECT id, title, status FROM variants WHERE options_hash = ? AND status IN ('approved','scheduled','ran') ORDER BY created_at ASC LIMIT 1",
    ).bind(optionsHash).first()
    : null;

  const now = Math.floor(Date.now() / 1000);
  const title = deriveTitle(normalized, Boolean(patch));

  // Every new variant waits for a human. The dials alone are a bounded menu and
  // could safely publish themselves, but a reader cannot tell which cards were
  // vetted and which merely passed a validator — so nothing appears on the
  // ballot under this project's name until someone has looked at it.
  const status = 'pending';

  const inserted = await env.DB.prepare(
    'INSERT INTO variants (spec_hash, options_hash, spec_json, title, claude_md_patch, rationale, status, created_at, submitter_id) '
    + 'VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING *',
  ).bind(
    specHash, optionsHash, JSON.stringify(normalized), title,
    patch || null, rationale || null, status, now, voterId,
  ).first();

  // The submitter's own vote rides along, so an approved variant arrives on the
  // ballot with the one vote it obviously has.
  await castVote(env, inserted.id, voterId, true);

  return json({
    outcome: 'created',
    // Built by hand rather than through publicVariant(): that function withholds
    // free text on a pending row, which is right for readers and wrong for the
    // person who just typed it. They see their own submission back, in full.
    variant: {
      id: inserted.id,
      title: inserted.title,
      spec: normalized,
      votes: 1,
      status,
      voted: true,
      claude_md_patch: patch || null,
      rationale: rationale || null,
      has_briefing_edit: Boolean(patch),
    },
    same_options_as: sibling || null,
    warnings,
  }, 201);
}

async function castVote(env, variantId, voterId, additive) {
  const now = Math.floor(Date.now() / 1000);
  if (additive) {
    const res = await env.DB.prepare(
      'INSERT OR IGNORE INTO votes (variant_id, voter_id, created_at) VALUES (?, ?, ?)',
    ).bind(variantId, voterId, now).run();
    return { added: res.meta.changes > 0, removed: false };
  }
  const res = await env.DB.prepare('DELETE FROM votes WHERE variant_id = ? AND voter_id = ?')
    .bind(variantId, voterId).run();
  return { added: false, removed: res.meta.changes > 0 };
}

async function handleVote(request, env, voterId) {
  const payload = await readJson(request);

  const turnstile = await verifyTurnstile(env, payload.turnstile_token, request);
  if (!turnstile.ok) return bad(turnstile.reason, turnstile.status);

  const limited = await rateLimit(env, 'vote', await ipHash(request, env));
  if (!limited.ok) {
    return bad(`too many votes from here — try again in ${Math.ceil(limited.retryAfter / 60)} minutes.`, 429);
  }

  const variantId = Number(payload.variant_id);
  if (!Number.isInteger(variantId) || variantId <= 0) return bad('variant_id must be a positive integer');

  const row = await env.DB.prepare('SELECT * FROM variants WHERE id = ?').bind(variantId).first();
  if (!row) return bad('no such variant', 404);
  if (!['approved', 'scheduled'].includes(row.status)) {
    return bad(row.status === 'ran' ? 'that round has already run' : 'that variant is not open for votes', 409);
  }

  const wantVote = payload.vote !== false;
  await castVote(env, variantId, voterId, wantVote);

  const after = await env.DB.prepare('SELECT vote_count FROM variants WHERE id = ?').bind(variantId).first();
  return json({ id: variantId, votes: after.vote_count, voted: wantVote });
}

/** The winning spec, ready to pipe into spec.py — the handoff from ballot to arena. */
async function handleVariantSpec(env, id) {
  const row = await env.DB.prepare('SELECT spec_json, status FROM variants WHERE id = ?').bind(id).first();
  if (!row) return bad('no such variant', 404);
  if (row.status === 'pending' || row.status === 'rejected') return bad('that variant is not published', 404);
  return new Response(JSON.stringify(JSON.parse(row.spec_json), null, 2), {
    headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' },
  });
}

/** Review queue. Free text is returned in full here — this is the human doing the reading. */
async function handleAdminQueue(env) {
  const { results } = await env.DB.prepare(
    "SELECT * FROM variants WHERE status = 'pending' ORDER BY created_at ASC LIMIT 100",
  ).all();
  return json({
    pending: results.map((r) => ({
      id: r.id,
      title: r.title,
      spec: JSON.parse(r.spec_json),
      claude_md_patch: r.claude_md_patch,
      rationale: r.rationale,
      votes: r.vote_count,
      created_at: r.created_at,
    })),
  });
}

async function handleAdminReview(request, env) {
  const payload = await readJson(request);
  const id = Number(payload.id);
  const status = payload.status;
  if (!Number.isInteger(id) || id <= 0) return bad('id must be a positive integer');
  if (!['approved', 'rejected', 'scheduled', 'ran', 'pending'].includes(status)) return bad('unknown status');

  const note = typeof payload.note === 'string' ? payload.note.slice(0, 500) : null;
  const roundNo = payload.round_no === undefined || payload.round_no === null ? null : Number(payload.round_no);
  if (roundNo !== null && !Number.isInteger(roundNo)) return bad('round_no must be an integer');

  const res = await env.DB.prepare(
    'UPDATE variants SET status = ?, review_note = ?, reviewed_at = ?, round_no = COALESCE(?, round_no) WHERE id = ?',
  ).bind(status, note, Math.floor(Date.now() / 1000), roundNo, id).run();

  if (!res.meta.changes) return bad('no such variant', 404);
  return json({ id, status });
}

// ── router ────────────────────────────────────────────────────────────────

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith('/api/')) return env.ASSETS.fetch(request);

    if (!env.BALLOT_SECRET) {
      console.error('ballot: BALLOT_SECRET is not set — refusing to serve the API');
      return bad('the ballot is not configured', 503);
    }

    const method = request.method.toUpperCase();
    if (method === 'OPTIONS') return new Response(null, { status: 204, headers: { allow: 'GET, POST' } });

    const setCookie = [];
    let voterId = await readVoter(request, env);
    if (!voterId) {
      const minted = await mintVoter(env);
      voterId = minted.id;
      setCookie.push(minted.cookie);
    }

    const withCookie = (response) => {
      if (!setCookie.length) return response;
      const out = new Response(response.body, response);
      for (const c of setCookie) out.headers.append('set-cookie', c);
      return out;
    };

    try {
      const path = url.pathname;

      if (method === 'GET' && path === '/api/menu') return withCookie(handleMenu(env));
      if (method === 'GET' && path === '/api/ballot') return withCookie(await handleBallot(request, env, voterId));

      const specMatch = /^\/api\/variants\/([0-9]+)\/spec$/.exec(path);
      if (method === 'GET' && specMatch) return withCookie(await handleVariantSpec(env, Number(specMatch[1])));

      if (method === 'POST') {
        if (!sameOrigin(request)) return bad('cross-origin writes are not accepted', 403);

        if (path === '/api/propose') return withCookie(await handlePropose(request, env, voterId));
        if (path === '/api/vote') return withCookie(await handleVote(request, env, voterId));

        if (path === '/api/admin/review') {
          if (!isAdmin(request, env)) return bad('not authorised', 401);
          return withCookie(await handleAdminReview(request, env));
        }
      }

      if (method === 'GET' && path === '/api/admin/queue') {
        if (!isAdmin(request, env)) return bad('not authorised', 401);
        return withCookie(await handleAdminQueue(env));
      }

      return bad('no such endpoint', 404);
    } catch (e) {
      if (e instanceof SpecError) return bad(e.message, 422);
      // Never swallow: an unexplained 500 here is a silent outage of the only
      // write path on the site.
      console.error('ballot: unhandled error on', url.pathname, '—', e && e.stack ? e.stack : e);
      return bad('something went wrong handling that request', 500);
    }
  },
};
