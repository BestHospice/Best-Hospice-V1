#!/usr/bin/env node
/**
 * Ingest one ARCHIVED hospice CMS release into the Phase A tables:
 * CmsRelease, CmsFacility, CmsFacilityServiceArea.
 *
 * DRY RUN BY DEFAULT. Writes require an explicit --write.
 *
 * The input is always a previously archived release on disk - never a live CMS
 * endpoint. Archives are produced by scripts/cms-archive.js and validated here
 * against data/cms-dataset-registry.json and the manifest's own sha256 values.
 *
 * Requires an Archive V2 manifest. Legacy pre-V2 archives are preserved on disk
 * as historical evidence but are not valid ingestion input: they do not record
 * source, status, datasetCount or headers, and this importer never infers
 * archive metadata.
 *
 * Archive family "hospice" maps to database source "cms_hospice". Those are
 * separate namespaces and are never compared by string equality; the mapping
 * comes from sources[] in the registry.
 *
 * Only `general` (facilities) and `zip` (service areas) are ingested. Quality,
 * CAHPS and benchmark datasets are deliberately out of scope for this phase.
 *
 *   node scripts/import-cms-hospice-data.js --release 2026-08-19
 *   node scripts/import-cms-hospice-data.js --release 2026-08-19 --no-db
 *   node scripts/import-cms-hospice-data.js --release 2026-08-19 --write
 *   node scripts/import-cms-hospice-data.js --list
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const ARCHIVE_ROOT = process.env.CMS_ARCHIVE_DIR
  ? path.resolve(process.env.CMS_ARCHIVE_DIR)
  : path.join(ROOT, 'reports', 'cms-archive');
const REGISTRY_PATH = process.env.CMS_REGISTRY_PATH
  ? path.resolve(process.env.CMS_REGISTRY_PATH)
  : path.join(ROOT, 'data', 'cms-dataset-registry.json');

const ARCHIVE_FAMILY = 'hospice';
const REQUIRED_FOR_INGEST = ['general', 'zip'];
const RELEASE_KEY_RE = /^\d{4}-\d{2}-\d{2}$/;

// Same guard philosophy as scripts/import-cms-hospice-identities.js. Applies to
// every mode that opens a connection, not just --write.
//
// Three distinct classes, deliberately NOT one flat list:
//   SHADOW          - never usable, and there is no authorization path to it.
//   PRODUCTION      - the one database we positively recognise as ours. Refused
//                     by default; a single release-scoped authorization exists.
//   HOSTED_UNKNOWN  - a managed database we cannot positively identify. Also
//                     refused with NO authorization path: we cannot prove what it
//                     is, so the only safe answer is no. Keeping this separate is
//                     what stops the authorization from becoming a generic key to
//                     any remote database.
// These are the strings that actually appear in a PostgreSQL connection URL -
// database name, role name and Render host id - not the Render dashboard display
// name. An earlier version listed only the display name, which never appears in a
// connection string, so a real shadow URL was not recognised as the shadow at all.
// The display name is kept as defence in depth.
//
// The user names are redundant under boundary matching (besthospice_shadow_2_user
// already contains besthospice_shadow_2 followed by a boundary character), but
// they are listed explicitly so the set stays correct even if the boundary rule
// is ever tightened, and so the list reads as the real inventory.
const SHADOW_IDENTIFIERS = [
  'besthospice_shadow_2',                 // databaseName
  'besthospice_shadow_2_user',            // databaseUser
  'dpg-d60g7h0gjchc73f306j0-a',           // Render host id
  'besthospice-shadow-2'                  // Render service/display name
];
const PRODUCTION_IDENTIFIERS = [
  'besthospice_db',                       // databaseName
  'besthospice_db_user',                  // databaseUser
  'dpg-d5hhmb4hg0os7380cecg-a'            // Render host id
];
const HOSTED_HOST_PATTERNS = /render\.com|\.rds\.amazonaws\.com|supabase\.co|neon\.tech/i;
// A Render Postgres internal hostname is a bare host id with no public suffix, so
// the patterns above cannot see it. Applied to the parsed HOSTNAME's first label
// only - never to arbitrary substrings - so a local database merely named
// something like "dpg-scratch" is unaffected.
const RENDER_HOST_ID_RE = /^dpg-[a-z0-9]{6,}(-[a-z])?$/;
// Used only for redacting log output, never for classification.
const FORBIDDEN_IDENTIFIERS = [...SHADOW_IDENTIFIERS, ...PRODUCTION_IDENTIFIERS];

// A one-time authorization is derived from the immutable facts of the exact
// release being ingested. It is not a secret and is not authentication - anyone
// with the archive can recompute it. Its whole job is to make an accidental,
// stale, or copy-pasted production run impossible: a token is worthless for any
// other release, manifest, or source, so no reusable bypass can exist.
const AUTHORIZATION_OPERATION = 'cms-hospice-production-ingest';
const AUTHORIZATION_TOKEN_RE = /^[0-9a-f]{64}$/;

const redact = (t) => String(t == null ? '' : t)
  .replace(/\b[a-z]+:\/\/[^\s"'`)]+/gi, '<redacted-url>')
  .replace(/(password|pgpassword)\s*[=:]\s*\S+/gi, '$1=<redacted>');
const scrub = (t) => FORBIDDEN_IDENTIFIERS.reduce(
  (a, id) => a.replace(new RegExp(id.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'gi'), '<redacted-identifier>'), redact(t));
const fail = (msg) => { console.error(`\n${redact(msg)}`); process.exit(1); };

// ---- CLI ------------------------------------------------------------------
const argv = process.argv.slice(2);
const opts = { write: false, noDb: false, release: null, list: false, json: null,
  productionAuthorization: null, printAuthorization: false };
const usage = (msg) => { console.error(`Usage error: ${msg}`); process.exit(2); };
// A value-taking flag must be followed by a real value. Without this, a typo
// like `--release --no-db` silently swallows the next flag, and a trailing
// `--release` silently falls back to "latest".
const takeValue = (flag, i) => {
  const v = argv[i + 1];
  if (v === undefined) usage(`${flag} requires a value.`);
  if (v.startsWith('--')) usage(`${flag} requires a value, but got the flag "${v}".`);
  return v;
};
for (let i = 0; i < argv.length; i++) {
  const a = argv[i];
  if (a === '--write') opts.write = true;
  else if (a === '--no-db') opts.noDb = true;
  else if (a === '--list') opts.list = true;
  else if (a === '--release') { opts.release = takeValue('--release', i); i++; }
  else if (a === '--json') { opts.json = takeValue('--json', i); i++; }
  else if (a === '--production-authorization') { opts.productionAuthorization = takeValue('--production-authorization', i); i++; }
  else if (a === '--print-production-authorization') opts.printAuthorization = true;
  else usage(`Unknown flag "${a}".`);
}
// Contradictory: --no-db means "never touch a database", --write means "write to
// one". Silently favouring either would ignore an explicit instruction.
if (opts.noDb && opts.write) usage('--no-db and --write are mutually exclusive.');
// Shape is a CLI concern and is checked before anything else happens. A token of
// the wrong shape can never be a real one, so there is no reason to read an
// archive or touch a database to find that out.
if (opts.productionAuthorization !== null && !AUTHORIZATION_TOKEN_RE.test(opts.productionAuthorization)) {
  usage('--production-authorization must be exactly 64 lowercase hexadecimal characters.');
}
if (opts.noDb && opts.productionAuthorization !== null) {
  usage('--no-db never contacts a database, so --production-authorization has no meaning with it.');
}
if (opts.printAuthorization && opts.write) {
  usage('--print-production-authorization never writes. Remove --write.');
}
if (opts.printAuthorization && opts.productionAuthorization !== null) {
  usage('--print-production-authorization computes a token; it does not consume one.');
}

// ---- CSV ------------------------------------------------------------------
// Hand-rolled and quote-aware. Nothing is coerced: a CCN like "A01500" or
// "031598" stays exactly the string CMS published.
function parseCsv(text) {
  const out = []; let row = []; let cur = ''; let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(cur); cur = ''; }
    else if (c === '\n') { row.push(cur); out.push(row); row = []; cur = ''; }
    else if (c !== '\r') cur += c;
  }
  if (cur !== '' || row.length) { row.push(cur); out.push(row); }
  const head = out.shift() || [];
  return { head, rows: out.filter((r) => r.some((v) => v !== '')).map((r) => Object.fromEntries(head.map((h, i) => [h, r[i] ?? '']))) };
}

// CMS missing-value sentinels. "-" is included: the real 2026-08-19 hospice
// general file uses it for 6057 Address Line 2, 61 County/Parish and 60
// Telephone Number values. It is applied ONLY to nullable descriptive fields -
// never to an identifier - and no identity column in the observed data ever
// holds a sentinel-looking value.
const NA = new Set(['', '-', 'Not Available', 'Not Applicable', 'N/A']);
const val = (v) => { const s = String(v ?? '').trim(); return NA.has(s) ? null : s; };
const req = (v) => { const s = String(v ?? '').trim(); return s === '' ? null : s; };
const certDate = (v) => {
  const s = val(v); if (!s) return null;
  const m = s.match(/^(\d{2})\/(\d{2})\/(\d{4})$/);
  if (!m) return undefined;                       // undefined = malformed, distinct from absent
  const [mm, dd, yyyy] = [Number(m[1]), Number(m[2]), Number(m[3])];
  const d = new Date(Date.UTC(yyyy, mm - 1, dd));
  // JS rolls impossible dates forward (02/30 -> Mar 1), which would store a date
  // CMS never published. Require the UTC components to survive construction
  // unchanged, so only real calendar dates are accepted. Leap days work: 2024
  // survives, 2023 does not.
  if (Number.isNaN(d.getTime())
    || d.getUTCFullYear() !== yyyy || d.getUTCMonth() !== mm - 1 || d.getUTCDate() !== dd) {
    return undefined;
  }
  return d;
};

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');
const loadRegistry = () => JSON.parse(fs.readFileSync(REGISTRY_PATH, 'utf8'));

// ---- archive discovery ----------------------------------------------------
function archiveCandidates() {
  const out = [];
  const v2 = path.join(ARCHIVE_ROOT, ARCHIVE_FAMILY);
  if (fs.existsSync(v2)) {
    for (const d of fs.readdirSync(v2).sort()) {
      if (fs.existsSync(path.join(v2, d, 'manifest.json'))) out.push({ key: d, dir: path.join(v2, d), layout: 'v2' });
    }
  }
  if (fs.existsSync(ARCHIVE_ROOT)) {
    for (const d of fs.readdirSync(ARCHIVE_ROOT).sort()) {
      const full = path.join(ARCHIVE_ROOT, d);
      if (!fs.statSync(full).isDirectory()) continue;
      if (!RELEASE_KEY_RE.test(d)) continue;                 // source dirs like home-health/
      if (out.some((o) => o.key === d)) continue;            // v2 wins
      if (fs.existsSync(path.join(full, 'manifest.json'))) out.push({ key: d, dir: full, layout: 'legacy' });
    }
  }
  return out.sort((a, b) => a.key.localeCompare(b.key));
}

// ---- archive validation ---------------------------------------------------
// Fail-closed. An Archive V2 manifest is required: source, status, datasetCount
// and per-file headers must be RECORDED FACTS, never inferred. On top of those,
// every used file is decompressed, its sha256 matched against the manifest, and
// its header matched against both the manifest and the tracked registry.
// Nothing is repaired and nothing is written back to the archive.
function validateArchive(reg, cand) {
  const problems = [];
  const note = [];
  const mfPath = path.join(cand.dir, 'manifest.json');
  if (!fs.existsSync(mfPath)) fail(`ARCHIVE INVALID: no manifest.json in ${path.relative(ROOT, cand.dir)}`);

  const rawManifest = fs.readFileSync(mfPath);            // raw bytes, hashed as-is
  const manifestSha256 = sha256(rawManifest);
  let mf;
  try { mf = JSON.parse(rawManifest.toString('utf8')); }
  catch (e) { fail(`ARCHIVE INVALID: manifest.json is not valid JSON (${e.message})`); }

  if (mf.releaseKey !== cand.key) {
    problems.push(`manifest releaseKey "${mf.releaseKey}" does not match archive directory "${cand.key}"`);
  }
  if (!RELEASE_KEY_RE.test(String(mf.releaseKey || ''))) {
    problems.push(`releaseKey "${mf.releaseKey}" is not YYYY-MM-DD; chronological ordering depends on that format`);
  }

  const hospiceCfg = reg.datasets.filter((d) => d.source === ARCHIVE_FAMILY);
  const files = mf.files || {};

  // --- Archive V2 manifest facts are REQUIRED, never derived ---
  // Phase B has exactly one archive contract. A legacy (pre-V2) manifest does not
  // record source, status or datasetCount, and it is not this importer's job to
  // reconstruct archive metadata - that is what Archive V2 exists for. Legacy
  // archives stay on disk as historical evidence; they are simply not ingestible.
  const missingFacts = [];
  if (mf.schemaVersion == null || Number(mf.schemaVersion) < 2) missingFacts.push('schemaVersion >= 2');
  if (mf.source == null) missingFacts.push('source');
  if (mf.status == null) missingFacts.push('status');
  if (mf.datasetCount == null) missingFacts.push('datasetCount');
  for (const k of REQUIRED_FOR_INGEST) {
    if (files[k] && !Array.isArray(files[k].headers)) missingFacts.push(`files.${k}.headers`);
  }
  if (missingFacts.length) {
    problems.push('Archive V2 manifest required for CMS ingestion. This archive is missing recorded '
      + `manifest fact(s): ${missingFacts.join(', ')}.\n`
      + '    Re-archive this release with the current archiver:\n'
      + `      node scripts/cms-archive.js --source ${ARCHIVE_FAMILY}\n`
      + '    The importer will not infer archive metadata.');
  } else {
    if (mf.source !== ARCHIVE_FAMILY) problems.push(`manifest source is "${mf.source}", expected "${ARCHIVE_FAMILY}"`);
    if (mf.status !== 'complete') problems.push(`manifest status is "${mf.status}", expected "complete"`);
  }

  // --- datasets this ingestion actually uses ---
  for (const k of REQUIRED_FOR_INGEST) {
    if (!files[k]) { problems.push(`required dataset "${k}" is absent from the manifest`); continue; }
    const gz = path.join(cand.dir, `${k}.csv.gz`);
    if (!fs.existsSync(gz)) problems.push(`required dataset "${k}" is in the manifest but ${k}.csv.gz is missing on disk`);
  }
  if (problems.length) {
    console.error('\nARCHIVE INVALID — refusing to ingest:');
    problems.forEach((p) => console.error(`  - ${p}`));
    process.exit(1);
  }

  // --- read, decompress, checksum, header-check every dataset we use ---
  const data = {};
  for (const k of REQUIRED_FOR_INGEST) {
    const gz = path.join(cand.dir, `${k}.csv.gz`);
    let raw;
    try { raw = zlib.gunzipSync(fs.readFileSync(gz)); }
    catch (e) { fail(`ARCHIVE INVALID: ${k}.csv.gz could not be decompressed (${e.message})`); }
    const got = sha256(raw);
    const want = files[k].sha256Raw;
    if (!want) fail(`ARCHIVE INVALID: manifest records no sha256Raw for "${k}"`);
    if (got !== want) fail(`ARCHIVE INVALID: ${k} checksum mismatch\n  manifest: ${want}\n  actual  : ${got}`);
    const parsed = parseCsv(raw.toString('utf8'));
    const cfg = hospiceCfg.find((d) => d.logicalKey === k);
    const exp = cfg.expectedHeaders || [];
    const rec = files[k].headers;              // recorded by Archive V2
    if (rec.length !== parsed.head.length || rec.some((h, i) => parsed.head[i] !== h)) {
      fail(`ARCHIVE INVALID: ${k} header does not match the headers recorded in the manifest`);
    }
    if (exp.length !== parsed.head.length || exp.some((h, i) => parsed.head[i] !== h)) {
      fail(`ARCHIVE INVALID: ${k} header does not match the registry contract\n`
        + `  expected (${exp.length}): ${exp.join(' | ')}\n`
        + `  actual   (${parsed.head.length}): ${parsed.head.join(' | ')}`);
    }
    data[k] = parsed.rows;
  }

  const datasetCount = mf.datasetCount;      // recorded fact, never inferred
  if (!mf.capturedAt) fail('ARCHIVE INVALID: manifest has no capturedAt');

  return {
    dir: cand.dir, layout: cand.layout, releaseKey: mf.releaseKey,
    capturedAt: new Date(mf.capturedAt), manifestSha256, datasetCount,
    datasetIds: Object.fromEntries(Object.entries(files).map(([k, f]) => [k, f.datasetId || null])),
    data, notes: note
  };
}

// ---- build intended rows --------------------------------------------------
const C = {
  ccn: 'CMS Certification Number (CCN)', name: 'Facility Name',
  a1: 'Address Line 1', a2: 'Address Line 2', city: 'City/Town', state: 'State',
  zip: 'ZIP Code', county: 'County/Parish', phone: 'Telephone Number',
  own: 'Ownership Type', cert: 'Certification Date'
};

function buildFacilities(rows) {
  const facilities = new Map();
  const invalid = [];
  let identicalDupes = 0;
  const conflicts = [];
  rows.forEach((r, i) => {
    const ccn = req(r[C.ccn]);
    const name = req(r[C.name]);
    const city = req(r[C.city]);
    const state = req(r[C.state]);
    const zip = req(r[C.zip]);
    const addr = [val(r[C.a1]), val(r[C.a2])].filter(Boolean).join(', ') || null;
    const cert = certDate(r[C.cert]);
    const why = [];
    if (!ccn) why.push('missing CCN');
    else if (!/^[0-9A-Z]{6}$/.test(ccn)) why.push(`malformed CCN "${ccn}"`);
    if (!name) why.push('missing Facility Name');
    if (!addr) why.push('missing Address');
    if (!city) why.push('missing City/Town');
    if (!state || !/^[A-Z]{2}$/.test(state)) why.push(`missing or malformed State "${state}"`);
    if (!zip || !/^\d{5}$/.test(String(zip).slice(0, 5))) why.push(`missing or malformed ZIP "${zip}"`);
    if (cert === undefined) why.push(`unparseable Certification Date "${r[C.cert]}"`);
    if (why.length) { invalid.push({ row: i + 2, ccn: ccn || '(none)', why: why.join('; ') }); return; }

    const rec = {
      ccn, name, address: addr, city, state, zip: String(zip).slice(0, 5),
      county: val(r[C.county]), phone: val(r[C.phone]), ownershipType: val(r[C.own]),
      certificationDate: cert
    };
    const prev = facilities.get(ccn);
    if (!prev) { facilities.set(ccn, rec); return; }
    if (JSON.stringify(prev) === JSON.stringify(rec)) { identicalDupes++; return; }
    conflicts.push(ccn);
  });
  return { facilities, invalid, identicalDupes, conflicts: [...new Set(conflicts)] };
}

function buildServiceAreas(rows, knownCcns) {
  const pairs = new Map();          // `${ccn}|${zip}`
  const invalid = [];
  let identicalDupes = 0;
  const orphanCcns = new Set();
  let orphanRows = 0;
  rows.forEach((r, i) => {
    const ccn = req(r[C.ccn]);
    const zipRaw = req(r[C.zip]);
    const zip = zipRaw ? String(zipRaw).slice(0, 5) : null;
    if (!ccn || !zip || !/^\d{5}$/.test(zip)) { invalid.push({ row: i + 2, ccn: ccn || '(none)', zip: zipRaw || '(none)' }); return; }
    if (!knownCcns.has(ccn)) { orphanCcns.add(ccn); orphanRows++; return; }
    const k = `${ccn}|${zip}`;
    if (pairs.has(k)) { identicalDupes++; return; }
    pairs.set(k, { ccn, zip });
  });
  return { pairs, invalid, identicalDupes, orphanCcns, orphanRows };
}

// ---- production guard -----------------------------------------------------
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

// Pure: string in, classification out. No connection, no side effects, so the
// tests can exercise every branch without credentials. Order matters - the shadow
// database is hosted on the same provider as production, so it must be recognised
// first and can never fall through to an authorizable class.
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

// The exact bytes hashed. Documented in docs/cms-data-pipeline.md so an operator
// can reproduce the token independently of this script.
function authorizationCanonical({ dbSource, releaseKey, manifestSha256 }) {
  return `${AUTHORIZATION_OPERATION}\n`
    + `source=${dbSource}\n`
    + `releaseKey=${releaseKey}\n`
    + `manifestSha256=${manifestSha256}\n`;
}
const authorizationToken = (facts) => sha256(Buffer.from(authorizationCanonical(facts), 'utf8'));

function tokenMatches(provided, expected) {
  const a = Buffer.from(String(provided == null ? '' : provided), 'utf8');
  const b = Buffer.from(expected, 'utf8');
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// `facts` are the immutable properties of the already-validated archive, so this
// can only ever be reached once the release is fully known.
function assertTargetAllowed(url, action, facts, token) {
  const verb = `Refusing to ${action}`;
  if (!url) fail(`${verb}: DATABASE_URL is not set.`);
  const target = classifyTarget(url);

  if (target.kind === 'SHADOW') {
    fail(`${verb}: DATABASE_URL points at the shadow database ("${target.matched}").\n`
      + '  The shadow database is never a valid ingestion target and there is no\n'
      + '  authorization that permits it. ZERO writes.');
  }
  if (target.kind === 'HOSTED_UNKNOWN') {
    fail(`${verb}: DATABASE_URL points at an unrecognised hosted/managed database.\n`
      + '  Only a disposable local database, or the one known production database\n'
      + '  with a release-scoped authorization, is a valid target. There is no\n'
      + '  authorization for an unrecognised host. ZERO writes.');
  }
  if (target.kind === 'PRODUCTION') {
    // Never echo the expected token here. A failed attempt must not hand the
    // operator the value that would have succeeded.
    if (token == null) {
      fail(`${verb}: DATABASE_URL points at the production database.\n`
        + '  Production is refused by default. A deliberate one-time ingestion of a\n'
        + `  specific release requires --production-authorization <64-hex>, scoped to\n`
        + `  source=${facts.dbSource}, releaseKey=${facts.releaseKey} and that release's\n`
        + '  exact manifestSha256.\n'
        + '  Compute it from the validated archive with:\n'
        + `    node scripts/import-cms-hospice-data.js --release ${facts.releaseKey} --print-production-authorization\n`
        + '  Authorization permits the connection only. Writing still requires --write.\n'
        + '  ZERO writes.');
    }
    if (!tokenMatches(token, authorizationToken(facts))) {
      fail(`${verb}: the supplied --production-authorization does not match this release.\n`
        + `  It must be derived from source=${facts.dbSource}, releaseKey=${facts.releaseKey}\n`
        + "  and this archive's exact manifestSha256. A token for any other release,\n"
        + '  manifest or source is rejected. ZERO writes.');
    }
    console.log('');
    console.log('!'.repeat(72));
    console.log(`!  PRODUCTION TARGET AUTHORIZED for ${facts.dbSource} release ${facts.releaseKey}`);
    console.log('!  Authorization is scoped to this release and manifest only.');
    console.log(`!  Mode: ${action === 'write' ? 'WRITE (--write supplied)' : 'READ-ONLY PLANNING (no --write)'}`);
    console.log('!'.repeat(72));
  }
}

const pad = (s, n) => String(s).padEnd(n);
const num = (n) => String(n).padStart(9);

(async () => {
  const reg = loadRegistry();
  const dbSource = (reg.sources || {})[ARCHIVE_FAMILY] && reg.sources[ARCHIVE_FAMILY].externalIdentitySource;
  if (!dbSource) fail(`registry has no sources["${ARCHIVE_FAMILY}"].externalIdentitySource mapping`);

  const cands = archiveCandidates();
  if (opts.list) {
    console.log(`archived ${ARCHIVE_FAMILY} releases under ${path.relative(ROOT, ARCHIVE_ROOT)}:`);
    if (!cands.length) console.log('  (none)');
    for (const c of cands) console.log(`  ${pad(c.key, 12)} ${pad(c.layout, 8)} ${path.relative(ROOT, c.dir)}`);
    return;
  }
  if (!cands.length) fail(`no archived ${ARCHIVE_FAMILY} release found under ${path.relative(ROOT, ARCHIVE_ROOT)}`);

  let cand;
  if (opts.release) {
    cand = cands.find((c) => c.key === opts.release);
    if (!cand) fail(`release "${opts.release}" not found. Available: ${cands.map((c) => c.key).join(', ')}`);
  } else {
    cand = cands[cands.length - 1];
    console.log(`No --release given; selecting the LATEST local archive deterministically.`);
  }

  const arc = validateArchive(reg, cand);
  const fac = buildFacilities(arc.data.general);
  const sa = buildServiceAreas(arc.data.zip, new Set(fac.facilities.keys()));
  const generalRowCount = arc.data.general.length;
  const zipRowCount = arc.data.zip.length;
  arc.data.general = null;          // the parsed CSV arrays are no longer needed;
  arc.data.zip = null;              // release them before any database work begins

  console.log('');
  console.log('='.repeat(78));
  console.log(`ARCHIVE`);
  console.log('='.repeat(78));
  console.log(`  archive path      : ${path.relative(ROOT, arc.dir)}  (${arc.layout} layout)`);
  console.log(`  source family     : ${ARCHIVE_FAMILY}`);
  console.log(`  mapped DB source  : ${dbSource}`);
  console.log(`  releaseKey        : ${arc.releaseKey}`);
  console.log(`  capturedAt        : ${arc.capturedAt.toISOString()}`);
  console.log(`  manifest sha256   : ${arc.manifestSha256}`);
  console.log(`  datasetCount      : ${arc.datasetCount}`);
  console.log(`  general dataset id: ${arc.datasetIds.general || '(not recorded)'}`);
  console.log(`  zip dataset id    : ${arc.datasetIds.zip || '(not recorded)'}`);
  for (const n of arc.notes) console.log(`  NOTE: ${n}`);

  console.log('');
  console.log('='.repeat(78));
  console.log('FACILITIES (general)');
  console.log('='.repeat(78));
  console.log(`  total rows                : ${num(generalRowCount)}`);
  console.log(`  valid facilities          : ${num(fac.facilities.size)}`);
  console.log(`  identical duplicate CCNs  : ${num(fac.identicalDupes)}  (collapsed)`);
  console.log(`  CONFLICTING duplicate CCNs: ${num(fac.conflicts.length)}`);
  console.log(`  invalid / skipped rows    : ${num(fac.invalid.length)}`);
  for (const iv of fac.invalid.slice(0, 5)) console.log(`      row ${iv.row} ccn=${iv.ccn}: ${iv.why}`);
  if (fac.invalid.length > 5) console.log(`      … and ${fac.invalid.length - 5} more`);
  if (fac.conflicts.length) {
    fail(`CONFLICTING duplicate CCNs in the archive: ${fac.conflicts.slice(0, 10).join(', ')}\n`
      + '  Two rows share a CCN with different descriptive values and CMS defines no\n'
      + '  resolution rule. Refusing to guess. ZERO writes.');
  }

  console.log('');
  console.log('='.repeat(78));
  console.log('SERVICE AREAS (zip)');
  console.log('='.repeat(78));
  console.log(`  total rows                : ${num(zipRowCount)}`);
  console.log(`  valid rows                : ${num(sa.pairs.size + sa.identicalDupes)}`);
  console.log(`  unique facility+ZIP pairs : ${num(sa.pairs.size)}`);
  console.log(`  identical duplicate pairs : ${num(sa.identicalDupes)}  (collapsed)`);
  console.log(`  malformed rows            : ${num(sa.invalid.length)}`);
  console.log(`  ORPHAN rows (unknown CCN) : ${num(sa.orphanRows)}  (${(100 * sa.orphanRows / Math.max(1, zipRowCount)).toFixed(2)}% of zip rows)`);
  console.log(`  distinct orphan CCNs      : ${num(sa.orphanCcns.size)}`);
  console.log(`      CMS publishes general and zip with different modified dates, so some`);
  console.log(`      certifications appear in one and not the other. Orphans are skipped and`);
  console.log(`      counted; no placeholder facility is created and no fuzzy matching occurs.`);

  const report = {
    archive: { path: path.relative(ROOT, arc.dir), layout: arc.layout, family: ARCHIVE_FAMILY, dbSource,
      releaseKey: arc.releaseKey, capturedAt: arc.capturedAt.toISOString(),
      manifestSha256: arc.manifestSha256, datasetCount: arc.datasetCount, datasetIds: arc.datasetIds },
    facilities: { totalRows: generalRowCount, valid: fac.facilities.size,
      identicalDuplicates: fac.identicalDupes, invalid: fac.invalid.length, invalidSamples: fac.invalid.slice(0, 20) },
    serviceAreas: { totalRows: zipRowCount, uniquePairs: sa.pairs.size,
      identicalDuplicates: sa.identicalDupes, malformed: sa.invalid.length,
      orphanRows: sa.orphanRows, orphanCcnCount: sa.orphanCcns.size, orphanCcns: [...sa.orphanCcns].sort() }
  };

  // Facts are fixed by the archive that has just been fully validated. Nothing
  // downstream can change them, which is what makes them safe to authorize against.
  const releaseFacts = { dbSource, releaseKey: arc.releaseKey, manifestSha256: arc.manifestSha256 };

  // Helper mode: derive the authorization for a validated archive. Never connects
  // to a database, never constructs a Prisma client, never mutates anything. It
  // exists so an operator does not have to hand-compute a SHA-256, and so a token
  // can only be produced for an archive that already passes every V2 check.
  if (opts.printAuthorization) {
    console.log('');
    console.log('='.repeat(78));
    console.log('PRODUCTION AUTHORIZATION (archive-only — no database was contacted)');
    console.log('='.repeat(78));
    console.log(`  operation      : ${AUTHORIZATION_OPERATION}`);
    console.log(`  source         : ${dbSource}`);
    console.log(`  releaseKey     : ${arc.releaseKey}`);
    console.log(`  manifestSha256 : ${arc.manifestSha256}`);
    console.log('');
    console.log(`  token          : ${authorizationToken(releaseFacts)}`);
    console.log('');
    console.log('  Valid for this release and manifest only. It is not a secret and not a');
    console.log('  credential; it proves the operator intended this exact release.');
    console.log('  It permits a production CONNECTION. Writing still requires --write.');
    return;
  }

  if (opts.noDb) {
    console.log('');
    console.log('ARCHIVE-ONLY VALIDATION (--no-db): no database was contacted and nothing was written.');
    if (opts.json) { fs.writeFileSync(opts.json, JSON.stringify(report, null, 2) + '\n'); console.log(`wrote ${opts.json}`); }
    return;
  }

  const url = process.env.DATABASE_URL;
  assertTargetAllowed(url, opts.write ? 'write' : 'open a database connection',
    releaseFacts, opts.productionAuthorization);

  const { PrismaClient } = require('@prisma/client');
  const prisma = new PrismaClient();
  try {
    // ---- chronology + idempotency, read-only first ----
    const existing = await prisma.cmsRelease.findUnique({
      where: { source_releaseKey: { source: dbSource, releaseKey: arc.releaseKey } } });
    const latest = await prisma.cmsRelease.findFirst({ where: { source: dbSource }, orderBy: { releaseKey: 'desc' } });

    // Chronology is decided by the LATEST ingested release for this source, never
    // by whether the requested release happens to exist. A release that is already
    // ingested but has since been superseded is an out-of-order ingestion attempt,
    // not an idempotent re-run: replaying it would drag lastSeenReleaseId backwards
    // and restore stale descriptive values. This runs before the plan is printed,
    // so a DB-backed dry run refuses it too.
    if (latest && latest.releaseKey > arc.releaseKey) {
      console.log('');
      fail(`CHRONOLOGY VIOLATION: release ${arc.releaseKey} is OLDER than the latest ingested `
        + `${dbSource} release ${latest.releaseKey}.\n`
        + (existing
          ? `  ${arc.releaseKey} is already ingested, but ${latest.releaseKey} has SUPERSEDED it.\n`
            + '  A superseded release is NOT an idempotent re-run — replaying it would move\n'
            + '  lastSeenReleaseId backwards and restore stale descriptive values.\n'
          : '')
        + '  Phase A current-state semantics depend on lastSeenReleaseId being the newest\n'
        + '  release, so backfilling an older release is refused. ZERO writes.');
    }

    let releaseAction = 'CREATE';
    if (existing) {
      releaseAction = 'UNCHANGED';
      const bad = [];
      if (existing.manifestSha256 == null) {
        bad.push('the stored release has a NULL manifestSha256, so this archive cannot be proven to be the one already ingested');
      } else if (existing.manifestSha256 !== arc.manifestSha256) {
        bad.push(`manifestSha256 differs (stored ${existing.manifestSha256}, archive ${arc.manifestSha256})`);
      }
      if (existing.capturedAt.getTime() !== arc.capturedAt.getTime()) {
        bad.push(`capturedAt differs (stored ${existing.capturedAt.toISOString()}, archive ${arc.capturedAt.toISOString()})`);
      }
      if (existing.datasetCount !== arc.datasetCount) {
        bad.push(`datasetCount differs (stored ${existing.datasetCount}, archive ${arc.datasetCount})`);
      }
      if (bad.length) {
        releaseAction = 'CONFLICT';
        console.log('');
        console.log('RELEASE CONFLICT — the archive does not match the release already ingested:');
        bad.forEach((b) => console.log(`  - ${b}`));
      }
    }

    // ---- classify facilities and service areas ----
    const dbFacilities = await prisma.cmsFacility.findMany({
      where: { source: dbSource },
      select: { id: true, ccn: true, lastSeenReleaseId: true, name: true, address: true, city: true,
                state: true, zip: true, county: true, phone: true, ownershipType: true, certificationDate: true } });
    const byCcn = new Map(dbFacilities.map((f) => [f.ccn, f]));
    const relId = existing ? existing.id : null;
    const dateEq = (a, b) => (a == null && b == null) ||
      (a != null && b != null && a.toISOString().slice(0, 10) === b.toISOString().slice(0, 10));
    const sameFacility = (db, want) => db.lastSeenReleaseId === relId
      && db.name === want.name && db.address === want.address && db.city === want.city
      && db.state === want.state && db.zip === want.zip && db.county === want.county
      && db.phone === want.phone && db.ownershipType === want.ownershipType
      && dateEq(db.certificationDate, want.certificationDate);

    let fCreate = 0, fUpdate = 0, fUnchanged = 0;
    for (const [ccn, want] of fac.facilities) {
      const db = byCcn.get(ccn);
      if (!db) fCreate++;
      else if (relId && sameFacility(db, want)) fUnchanged++;
      else fUpdate++;
    }
    const absentFacilities = dbFacilities.filter((f) => !fac.facilities.has(f.ccn)).length;

    // Service-area classification is set-based in PostgreSQL. Loading the existing
    // ~342k rows into JS and building a same-sized Map peaked at 1.24 GB on a
    // populated database. Instead the intended pairs are streamed to the server in
    // chunks and classified by a join against unnest(), so peak JS memory is one
    // chunk regardless of table size. This is not N+1: ~69 queries for 342k pairs.
    // No transaction, no temp table - a dry run still opens nothing and writes
    // nothing.
    const SA_CLASSIFY_CHUNK = 5000;
    let sCreate = 0, sUpdate = 0, sUnchanged = 0;
    {
      const it = sa.pairs.values();
      let ccns = [], zips = [], done = false;
      const flush = async () => {
        if (!ccns.length) return;
        const [row] = await prisma.$queryRawUnsafe(
          `SELECT
             count(*) FILTER (WHERE e.id IS NULL)::int                                    AS creates,
             count(*) FILTER (WHERE e.id IS NOT NULL
                                AND e."lastSeenReleaseId" IS DISTINCT FROM $3::text)::int AS updates,
             count(*) FILTER (WHERE e.id IS NOT NULL
                                AND e."lastSeenReleaseId" = $3::text)::int                AS unchanged
           FROM unnest($1::text[], $2::text[]) AS t(ccn, zip)
           LEFT JOIN "CmsFacility" f
             ON f.source = $4::text AND f.ccn = t.ccn
           LEFT JOIN "CmsFacilityServiceArea" e
             ON e."facilityId" = f.id AND e.zip = t.zip`,
          ccns, zips, relId, dbSource);
        sCreate += row.creates; sUpdate += row.updates; sUnchanged += row.unchanged;
        ccns = []; zips = [];
      };
      while (!done) {
        const n = it.next();
        if (n.done) { done = true; } else { ccns.push(n.value.ccn); zips.push(n.value.zip); }
        if (done || ccns.length >= SA_CLASSIFY_CHUNK) await flush();
      }
    }
    // Intended pairs are unique and (facilityId, zip) is unique, so each existing
    // row matches at most one intended pair. Everything not matched is therefore
    // absent - no second full scan of the table is needed to count it.
    const totalDbSas = await prisma.cmsFacilityServiceArea.count({ where: { source: dbSource } });
    const absentSas = totalDbSas - (sUpdate + sUnchanged);

    console.log('');
    console.log('='.repeat(78));
    console.log(`PLAN  (${opts.write ? 'WRITE MODE' : 'DRY RUN — ZERO WRITES'})`);
    console.log('='.repeat(78));
    console.log(`  release           : ${releaseAction}   ${dbSource} / ${arc.releaseKey}`);
    console.log(`  chronology        : ${existing ? 'same release (idempotent re-run)' : latest ? `later than ${latest.releaseKey} — OK` : 'first release for this source — OK'}`);
    console.log(`  facilities        : CREATE ${fCreate}   UPDATE ${fUpdate}   UNCHANGED ${fUnchanged}   absent-from-release ${absentFacilities} (retained, lastSeen untouched)`);
    console.log(`  service areas     : CREATE ${sCreate}   UPDATE ${sUpdate}   UNCHANGED ${sUnchanged}   absent-from-release ${absentSas} (retained, lastSeen untouched)`);
    console.log(`  observations      : APPEND ${fac.facilities.size} for this release (append-only; earlier releases untouched)`);

    report.plan = { releaseAction,
      facilities: { create: fCreate, update: fUpdate, unchanged: fUnchanged, absent: absentFacilities },
      serviceAreas: { create: sCreate, update: sUpdate, unchanged: sUnchanged, absent: absentSas },
      observations: { append: fac.facilities.size } };
    if (opts.json) { fs.writeFileSync(opts.json, JSON.stringify(report, null, 2) + '\n'); console.log(`\n  wrote ${opts.json}`); }

    if (releaseAction === 'CONFLICT') fail('Refusing to write: release conflict. ZERO rows written.');

    if (!opts.write) {
      console.log('');
      console.log('DRY RUN — nothing was written. Re-run with --write to apply.');
      return;
    }
    if (releaseAction === 'UNCHANGED' && fCreate === 0 && fUpdate === 0 && sCreate === 0 && sUpdate === 0) {
      console.log('\nAlready ingested and unchanged. No transaction opened.');
      return;
    }

    console.log('\n' + '*'.repeat(72));
    console.log(`*  WRITE MODE ACTIVE — ingesting ${dbSource} release ${arc.releaseKey}`);
    console.log('*'.repeat(72));

    const t0 = Date.now();
    await prisma.$transaction(async (tx) => {
      // FIRST statement: serialise ingestion per source. Without this, two
      // different later releases can both pass the chronology check under READ
      // COMMITTED (neither sees the other's uncommitted CmsRelease) and the
      // surviving lastSeenReleaseId ends up decided by commit order rather than
      // releaseKey. Transaction-scoped, so it releases on commit or rollback.
      await tx.$executeRawUnsafe('SELECT pg_advisory_xact_lock(hashtext($1))', `cms-ingest:${dbSource}`);

      // Re-check preconditions AFTER the lock is held.
      const cur = await tx.cmsRelease.findUnique({
        where: { source_releaseKey: { source: dbSource, releaseKey: arc.releaseKey } } });
      const newest = await tx.cmsRelease.findFirst({ where: { source: dbSource }, orderBy: { releaseKey: 'desc' } });
      // Authoritative for writes, and deliberately NOT conditioned on `cur`: an
      // already-ingested but superseded release must be refused here too.
      if (newest && newest.releaseKey > arc.releaseKey) {
        throw new Error(`chronology violation detected inside the transaction: ${arc.releaseKey} is older than ${newest.releaseKey}`);
      }
      if (cur && cur.manifestSha256 && cur.manifestSha256 !== arc.manifestSha256) throw new Error('manifest changed inside the transaction');

      const rel = cur || await tx.cmsRelease.create({ data: {
        source: dbSource, releaseKey: arc.releaseKey, capturedAt: arc.capturedAt,
        datasetCount: arc.datasetCount, manifestSha256: arc.manifestSha256 } });

      // Facilities. ON CONFLICT updates descriptive fields and lastSeen only;
      // firstSeenReleaseId is deliberately absent from the SET list so it is preserved.
      const fRows = [...fac.facilities.values()];
      for (let i = 0; i < fRows.length; i += 500) {
        const chunk = fRows.slice(i, i + 500);
        const params = []; const tuples = [];
        chunk.forEach((f) => {
          const b = params.length;
          // Pass the date as a plain YYYY-MM-DD string, never a JS Date. The pg
          // driver serialises a Date in LOCAL time, so `::date` truncates it to the
          // previous day in any negative UTC offset - a silent off-by-one.
          params.push(crypto.randomUUID(), dbSource, f.ccn, f.name, f.address, f.city, f.state, f.zip,
            f.county, f.phone, f.ownershipType,
            f.certificationDate ? f.certificationDate.toISOString().slice(0, 10) : null, rel.id, rel.id);
          tuples.push(`($${b+1},$${b+2},$${b+3},$${b+4},$${b+5},$${b+6},$${b+7},$${b+8},$${b+9},$${b+10},$${b+11},$${b+12}::date,$${b+13},$${b+14},NOW(),NOW())`);
        });
        await tx.$executeRawUnsafe(
          `INSERT INTO "CmsFacility" ("id","source","ccn","name","address","city","state","zip","county","phone","ownershipType","certificationDate","firstSeenReleaseId","lastSeenReleaseId","createdAt","updatedAt")
           VALUES ${tuples.join(',')}
           ON CONFLICT ("source","ccn") DO UPDATE SET
             "name"=EXCLUDED."name", "address"=EXCLUDED."address", "city"=EXCLUDED."city",
             "state"=EXCLUDED."state", "zip"=EXCLUDED."zip", "county"=EXCLUDED."county",
             "phone"=EXCLUDED."phone", "ownershipType"=EXCLUDED."ownershipType",
             "certificationDate"=EXCLUDED."certificationDate",
             "lastSeenReleaseId"=EXCLUDED."lastSeenReleaseId", "updatedAt"=NOW()`, ...params);
      }

      const idRows = await tx.cmsFacility.findMany({ where: { source: dbSource }, select: { id: true, ccn: true } });
      const ccnToId = new Map(idRows.map((r) => [r.ccn, r.id]));

      // Append-only history: one CmsFacilityObservation per facility per release.
      //
      // Every value comes from `fac.facilities`, which is the PARSED ARCHIVE - never
      // from the CmsFacility rows just written. That matters for three reasons: the
      // observation is a pure function of the release bytes, it cannot inherit a
      // value the upsert happened to leave behind, and it stays correct regardless
      // of where in the transaction this runs.
      //
      // The conflict target is (facilityId, releaseId), so this is idempotent for a
      // re-run of the SAME release and structurally incapable of touching an older
      // one: a different release has a different releaseId and therefore inserts a
      // new row. No release can ever update another release's observation.
      const oRows = [...fac.facilities.values()];
      for (let i = 0; i < oRows.length; i += 500) {
        const chunk = oRows.slice(i, i + 500);
        const params = []; const tuples = [];
        chunk.forEach((f) => {
          const b = params.length;
          // Same date handling as the facility upsert: pass YYYY-MM-DD as text, never
          // a JS Date, or the pg driver's local-time serialisation shifts ::date back
          // a day in any negative UTC offset.
          params.push(crypto.randomUUID(), ccnToId.get(f.ccn), dbSource, rel.id, f.ccn,
            f.name, f.address, f.city, f.state, f.zip, f.county, f.phone, f.ownershipType,
            f.certificationDate ? f.certificationDate.toISOString().slice(0, 10) : null);
          tuples.push(`($${b+1},$${b+2},$${b+3},$${b+4},$${b+5},$${b+6},$${b+7},$${b+8},$${b+9},$${b+10},$${b+11},$${b+12},$${b+13},$${b+14}::date,NOW())`);
        });
        await tx.$executeRawUnsafe(
          `INSERT INTO "CmsFacilityObservation" ("id","facilityId","source","releaseId","ccn","name","address","city","state","zip","county","phone","ownershipType","certificationDate","createdAt")
           VALUES ${tuples.join(',')}
           ON CONFLICT ("facilityId","releaseId") DO UPDATE SET
             "ccn"=EXCLUDED."ccn", "name"=EXCLUDED."name", "address"=EXCLUDED."address",
             "city"=EXCLUDED."city", "state"=EXCLUDED."state", "zip"=EXCLUDED."zip",
             "county"=EXCLUDED."county", "phone"=EXCLUDED."phone",
             "ownershipType"=EXCLUDED."ownershipType",
             "certificationDate"=EXCLUDED."certificationDate"`, ...params);
      }

      const sRows = [...sa.pairs.values()];
      for (let i = 0; i < sRows.length; i += 2000) {
        const chunk = sRows.slice(i, i + 2000);
        const params = []; const tuples = [];
        chunk.forEach((s) => {
          const b = params.length;
          params.push(crypto.randomUUID(), ccnToId.get(s.ccn), dbSource, s.zip, rel.id, rel.id);
          tuples.push(`($${b+1},$${b+2},$${b+3},$${b+4},$${b+5},$${b+6},NOW())`);
        });
        await tx.$executeRawUnsafe(
          `INSERT INTO "CmsFacilityServiceArea" ("id","facilityId","source","zip","firstSeenReleaseId","lastSeenReleaseId","createdAt")
           VALUES ${tuples.join(',')}
           ON CONFLICT ("facilityId","zip") DO UPDATE SET "lastSeenReleaseId"=EXCLUDED."lastSeenReleaseId"`, ...params);
      }

      // Postconditions inside the transaction.
      const nf = await tx.cmsFacility.count({ where: { source: dbSource, lastSeenReleaseId: rel.id } });
      if (nf !== fac.facilities.size) throw new Error(`postcondition: ${nf} facilities carry this release, expected ${fac.facilities.size}`);
      const ns = await tx.cmsFacilityServiceArea.count({ where: { source: dbSource, lastSeenReleaseId: rel.id } });
      if (ns !== sa.pairs.size) throw new Error(`postcondition: ${ns} service areas carry this release, expected ${sa.pairs.size}`);
      // History postcondition. Scoped to THIS release, so it is unaffected by how
      // many observations earlier releases left behind.
      const no = await tx.cmsFacilityObservation.count({ where: { source: dbSource, releaseId: rel.id } });
      if (no !== fac.facilities.size) throw new Error(`postcondition: ${no} facility observations carry this release, expected ${fac.facilities.size}`);
    }, { timeout: 600000, maxWait: 60000 });

    const totals = {
      releases: await prisma.cmsRelease.count({ where: { source: dbSource } }),
      facilities: await prisma.cmsFacility.count({ where: { source: dbSource } }),
      serviceAreas: await prisma.cmsFacilityServiceArea.count({ where: { source: dbSource } }),
      observations: await prisma.cmsFacilityObservation.count({ where: { source: dbSource } })
    };
    console.log(`\nINGESTED release ${arc.releaseKey} in one transaction (${((Date.now() - t0) / 1000).toFixed(1)}s).`);
    console.log(`  CmsRelease ${totals.releases}   CmsFacility ${totals.facilities}   CmsFacilityServiceArea ${totals.serviceAreas}   CmsFacilityObservation ${totals.observations}`);
  } finally {
    if (typeof prisma !== 'undefined') await prisma.$disconnect().catch(() => {});
  }
})().catch((e) => {
  const detail = [e && e.message, e && e.code && `code ${e.code}`].filter(Boolean).join(' | ') || String(e);
  console.error(`\nINGESTION FAILED — transaction rolled back, ZERO rows written.\n  ${scrub(detail).split('\n').slice(-4).join('\n  ')}`);
  process.exit(1);
});
