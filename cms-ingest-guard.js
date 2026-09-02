'use strict';
/**
 * Shared database-target classification and release-scoped authorization for
 * every CMS ingestion script.
 *
 * This is a LEAF MODULE by design: it requires only node:crypto, so a test can
 * exercise every branch with no database, no credentials and no side effects.
 *
 * WHY THIS EXISTS SEPARATELY
 * scripts/import-cms-hospice-data.js grew this logic first and carries its own
 * copy. Rather than reimplement it in the quality ingester - where the two
 * copies would silently drift and one of them would eventually stop recognising
 * the real production or shadow database - the logic lives here once. The
 * facility importer is deliberately left byte-for-byte unchanged, and
 * scripts/test-cms-quality-ingestion.js asserts that its literal identifier
 * lists are IDENTICAL to the ones exported here, so divergence is a test
 * failure rather than a silent safety hole.
 *
 * There is deliberately NO generic bypass. No --force, --allow-production,
 * --unsafe or --skip-guard exists anywhere in this module, and authorization is
 * scoped so narrowly that a token cannot be reused for a different operation,
 * source, release or archive.
 */
const crypto = require('crypto');

// Three distinct classes, deliberately NOT one flat list:
//   SHADOW          - never usable, and there is no authorization path to it.
//   PRODUCTION      - the one database we positively recognise as ours. Refused
//                     by default; a single scoped authorization exists.
//   HOSTED_UNKNOWN  - a managed database we cannot positively identify. Also
//                     refused, with NO authorization path: we cannot prove what
//                     it is, so the only safe answer is no. Keeping this class
//                     separate is what stops the authorization from becoming a
//                     generic key to any remote database.
//
// These are the strings that actually appear in a PostgreSQL connection URL -
// database name, role name and Render host id - not the Render dashboard display
// name. The display name is kept as defence in depth.
const SHADOW_IDENTIFIERS = Object.freeze([
  'besthospice_shadow_2',                 // databaseName
  'besthospice_shadow_2_user',            // databaseUser
  'dpg-d60g7h0gjchc73f306j0-a',           // Render host id
  'besthospice-shadow-2'                  // Render service/display name
]);
const PRODUCTION_IDENTIFIERS = Object.freeze([
  'besthospice_db',                       // databaseName
  'besthospice_db_user',                  // databaseUser
  'dpg-d5hhmb4hg0os7380cecg-a'            // Render host id
]);
const HOSTED_HOST_PATTERNS = /render\.com|\.rds\.amazonaws\.com|supabase\.co|neon\.tech/i;
// A Render Postgres internal hostname is a bare host id with no public suffix, so
// the patterns above cannot see it. Applied to the parsed HOSTNAME's first label
// only - never to arbitrary substrings - so a local database merely named
// something like "dpg-scratch" is unaffected.
const RENDER_HOST_ID_RE = /^dpg-[a-z0-9]{6,}(-[a-z])?$/;
// Used only for redacting log output, never for classification.
const FORBIDDEN_IDENTIFIERS = Object.freeze([...SHADOW_IDENTIFIERS, ...PRODUCTION_IDENTIFIERS]);

const AUTHORIZATION_TOKEN_RE = /^[0-9a-f]{64}$/;

const sha256Hex = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

const redact = (t) => String(t == null ? '' : t)
  .replace(/\b[a-z]+:\/\/[^\s"'`)]+/gi, '<redacted-url>')
  .replace(/(password|pgpassword)\s*[=:]\s*\S+/gi, '$1=<redacted>');
const scrub = (t) => FORBIDDEN_IDENTIFIERS.reduce(
  (a, id) => a.replace(new RegExp(id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), '<redacted-identifier>'),
  redact(t));

// Every representation of the URL an operator could plausibly supply. Substring
// matching on the raw string alone missed percent-encoded identifiers such as
// "besthospice%5Fdb". A malformed URL simply yields fewer candidates - it never
// skips the check.
function guardCandidates(url) {
  const out = new Set();
  const add = (v) => { if (typeof v === 'string' && v) out.add(v.toLowerCase().replace(/\s+/g, '')); };
  const raw = String(url == null ? '' : url);
  add(raw);
  let decoded = raw;
  for (let i = 0; i < 3; i++) {                 // tolerate double-encoding
    try { const d = decodeURIComponent(decoded); if (d === decoded) break; decoded = d; add(d); }
    catch { break; }
  }
  for (const candidate of [raw, decoded]) {
    try {
      const u = new URL(candidate);
      add(u.hostname); add(u.pathname); add(u.search);
      try { add(decodeURIComponent(u.hostname)); } catch { /* keep the encoded form */ }
      try { add(decodeURIComponent(u.pathname)); } catch { /* keep the encoded form */ }
    } catch { /* malformed: the raw and decoded strings are still checked */ }
  }
  return [...out];
}

// Match an identifier only as a WHOLE identifier. Plain substring matching made
// "besthospice_db1" look like the production database "besthospice_db", which
// would have let a production authorization reach a different database. A
// boundary is anything that is not [a-z0-9], so "_user" and "-a" suffixes still
// match while a trailing digit does not.
function containsIdentifier(hay, id) {
  const esc = id.toLowerCase().replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
  return new RegExp(`(^|[^a-z0-9])${esc}([^a-z0-9]|$)`).test(hay);
}

// Parsed hostnames, across every decoding of the URL. Kept separate from the
// loose candidate set so host-shaped rules are only ever applied to a hostname.
function targetHostnames(url) {
  const raw = String(url == null ? '' : url).replace(/\s+/g, '');
  const forms = [raw];
  let d = raw;
  for (let i = 0; i < 3; i++) {
    try { const n = decodeURIComponent(d); if (n === d) break; d = n; forms.push(n); } catch { break; }
  }
  const hosts = new Set();
  for (const f of forms) {
    try { const u = new URL(f); if (u.hostname) hosts.add(u.hostname.toLowerCase()); } catch { /* not a URL */ }
  }
  return [...hosts];
}
const isRenderHost = (hostname) => RENDER_HOST_ID_RE.test(String(hostname).split('.')[0]);

// Pure: string in, classification out. No connection, no side effects. Order
// matters - the shadow database is hosted on the same provider as production, so
// it must be recognised first and can never fall through to an authorizable class.
function classifyTarget(url) {
  const cands = guardCandidates(url);
  const hosts = targetHostnames(url);
  const hit = (list) => list.find((id) => cands.some((c) => containsIdentifier(c, id)));

  const shadow = hit(SHADOW_IDENTIFIERS);
  if (shadow) return { kind: 'SHADOW', matched: shadow };
  const prod = hit(PRODUCTION_IDENTIFIERS);
  if (prod) return { kind: 'PRODUCTION', matched: prod };
  if (cands.some((c) => HOSTED_HOST_PATTERNS.test(c))) return { kind: 'HOSTED_UNKNOWN', matched: null };
  // An unrecognised Render database reached by its internal host id. Refused with
  // no authorization path: we cannot prove which database it is.
  if (hosts.some(isRenderHost)) return { kind: 'HOSTED_UNKNOWN', matched: null };
  return { kind: 'NON_PRODUCTION', matched: null };
}

// A one-time authorization derived from the immutable facts of the exact release
// being ingested. It is not a secret and is not authentication - anyone with the
// archive can recompute it. Its whole job is to make an accidental, stale or
// copy-pasted production run impossible.
//
// `operation` is part of the hashed bytes, so the token that authorizes a
// facility ingestion of a release CANNOT authorize a quality ingestion of that
// same release, and vice versa. Each production step is authorized on its own.
function authorizationCanonical({ operation, dbSource, releaseKey, manifestSha256 }) {
  return `${operation}\n`
    + `source=${dbSource}\n`
    + `releaseKey=${releaseKey}\n`
    + `manifestSha256=${manifestSha256}\n`;
}
const authorizationToken = (facts) => sha256Hex(Buffer.from(authorizationCanonical(facts), 'utf8'));

function tokenMatches(provided, expected) {
  const a = Buffer.from(String(provided == null ? '' : provided), 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) return false;      // timingSafeEqual requires equal lengths
  return crypto.timingSafeEqual(a, b);
}

module.exports = {
  SHADOW_IDENTIFIERS, PRODUCTION_IDENTIFIERS, FORBIDDEN_IDENTIFIERS,
  HOSTED_HOST_PATTERNS, RENDER_HOST_ID_RE, AUTHORIZATION_TOKEN_RE,
  sha256Hex, redact, scrub,
  guardCandidates, containsIdentifier, targetHostnames, isRenderHost, classifyTarget,
  authorizationCanonical, authorizationToken, tokenMatches
};
