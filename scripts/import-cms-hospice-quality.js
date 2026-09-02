#!/usr/bin/env node
'use strict';
/**
 * CMS hospice QUALITY ingestion — Quality Intelligence V1.
 *
 * Loads CmsMeasureDefinition and CmsFacilityMeasure from an already-validated
 * local Archive V2 release. Reads the archive on disk; never contacts CMS.
 *
 * DRY RUN IS THE DEFAULT. Without --write nothing is written, and the plan it
 * prints is computed with the same code that would do the writing.
 *
 * PRECONDITION: the release must ALREADY be ingested by
 * scripts/import-cms-hospice-data.js. Measurements are foreign-keyed to
 * CmsFacility and CmsRelease, so there is nothing to attach them to otherwise.
 * This script therefore never creates a CmsRelease - it looks one up, checks its
 * manifestSha256 matches this archive byte-for-byte, and refuses if it does not.
 * That keeps one writer for the release row and makes it impossible to load
 * quality data from a different archive than the facilities came from.
 *
 * FAIL-CLOSED, in this order:
 *   1. Archive V2 manifest facts must be RECORDED, never inferred.
 *   2. Every used file's sha256 must match the manifest.
 *   3. Every used file's header must match both the manifest and the tracked
 *      registry contract.
 *   4. Every measure code in data/cms-hospice-quality-measures.json must be
 *      PRESENT in its dataset, and CMS's own Measure Name for it must match the
 *      recorded name exactly. A CMS redefinition is an error, not a relabelling.
 *   5. Every cell must parse into a documented shape. "Yes", a novel sentinel or
 *      an unknown period format aborts the run rather than silently nulling.
 *
 * SUPPRESSION IS DATA. A measure CMS withheld is stored as a row with
 * suppressed = true, valueNumeric = null and the raw CMS text preserved. It is
 * never zero, never imputed and never omitted, so "CMS published nothing" stays
 * distinguishable from "we never ingested this".
 *
 * There is NO generic production bypass. No --force, --allow-production,
 * --unsafe or --skip-guard exists. Production requires a token derived from this
 * exact operation, source, release and manifest, and a facility-ingestion token
 * cannot authorize a quality ingestion.
 *
 *   node scripts/import-cms-hospice-quality.js --list
 *   node scripts/import-cms-hospice-quality.js --release 2026-08-19 --no-db
 *   DATABASE_URL=postgresql://…/local_disposable \
 *     node scripts/import-cms-hospice-quality.js --release 2026-08-19
 *   DATABASE_URL=postgresql://…/local_disposable \
 *     node scripts/import-cms-hospice-quality.js --release 2026-08-19 --write
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const guard = require(path.join(ROOT, 'cms-ingest-guard.js'));
const {
  QualityParseError, parseCsv,
  parseScoreCell, parseFootnoteCell, parsePeriodCell, parseStarRatingCell, parseDenominatorCell
} = require(path.join(ROOT, 'cms-quality-parse.js'));

const ARCHIVE_ROOT = process.env.CMS_ARCHIVE_DIR
  ? path.resolve(process.env.CMS_ARCHIVE_DIR)
  : path.join(ROOT, 'reports', 'cms-archive');
const REGISTRY_PATH = process.env.CMS_REGISTRY_PATH
  ? path.resolve(process.env.CMS_REGISTRY_PATH)
  : path.join(ROOT, 'data', 'cms-dataset-registry.json');
const MEASURES_PATH = process.env.CMS_QUALITY_MEASURES_PATH
  ? path.resolve(process.env.CMS_QUALITY_MEASURES_PATH)
  : path.join(ROOT, 'data', 'cms-hospice-quality-measures.json');

const ARCHIVE_FAMILY = 'hospice';
// The datasets this ingestion reads. Deliberately narrow: the facility importer
// owns general/zip and this one owns the two quality files.
const REQUIRED_FOR_INGEST = ['provider', 'cahps_provider'];
const RELEASE_KEY_RE = /^\d{4}-\d{2}-\d{2}$/;

// Distinct from the facility importer's operation string, so the two production
// steps are authorized separately and neither token works for the other.
const AUTHORIZATION_OPERATION = 'cms-hospice-quality-ingest';

const COL = {
  ccn: 'CMS Certification Number (CCN)',
  code: 'Measure Code',
  name: 'Measure Name',
  score: 'Score',
  star: 'Star Rating',
  footnote: 'Footnote'
};
// The provider file names its period column "Measure Date Range"; the CAHPS file
// calls it "Date" and formats it without spaces around the dash.
const PERIOD_COL = { provider: 'Measure Date Range', cahps_provider: 'Date' };

const fail = (msg) => { console.error(`\n${guard.redact(msg)}`); process.exit(1); };
const sha256 = guard.sha256Hex;

// ---- CLI ------------------------------------------------------------------
const argv = process.argv.slice(2);
const opts = { write: false, noDb: false, release: null, list: false, json: null,
  productionAuthorization: null, printAuthorization: false };
const usage = (msg) => { console.error(`Usage error: ${msg}`); process.exit(2); };
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
if (opts.noDb && opts.write) usage('--no-db and --write are mutually exclusive.');
if (opts.productionAuthorization !== null && !guard.AUTHORIZATION_TOKEN_RE.test(opts.productionAuthorization)) {
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

// ---- registries -----------------------------------------------------------
const loadJson = (p) => JSON.parse(fs.readFileSync(p, 'utf8'));

function loadMeasureRegistry() {
  const reg = loadJson(MEASURES_PATH);
  const problems = [];
  if (reg.source !== 'cms_hospice') problems.push(`source is "${reg.source}", expected "cms_hospice"`);
  if (!Array.isArray(reg.measures) || !reg.measures.length) problems.push('no measures declared');
  const dims = new Set((reg.dimensions || []).map((d) => d.key));
  const seen = new Set();
  for (const m of reg.measures || []) {
    const at = `measure "${m.measureCode}"`;
    if (!m.measureCode) problems.push('a measure has no measureCode');
    if (seen.has(m.measureCode)) problems.push(`${at} is declared twice`);
    seen.add(m.measureCode);
    if (!REQUIRED_FOR_INGEST.includes(m.dataset)) problems.push(`${at} names dataset "${m.dataset}", which this ingestion does not read`);
    if (!m.cmsMeasureName) problems.push(`${at} has no recorded cmsMeasureName, so CMS drift could not be detected`);
    if (!m.shortLabel) problems.push(`${at} has no shortLabel`);
    if (!dims.has(m.dimension)) problems.push(`${at} names undeclared dimension "${m.dimension}"`);
    // The whole point of the registry. A measure with no direction cannot be
    // compared at all, so it must never reach the database.
    if (m.direction !== 'higher_better' && m.direction !== 'lower_better') {
      problems.push(`${at} has direction "${m.direction}"; only higher_better or lower_better are supported`);
    }
    if (!['index', 'percent', 'stars'].includes(m.valueKind)) problems.push(`${at} has unsupported valueKind "${m.valueKind}"`);
    if (!Number.isInteger(m.decimals)) problems.push(`${at} has non-integer decimals`);
    // CMS's raw percentile is a monotone rank of the raw value with no
    // directional correction, so on a lower-is-better measure a higher CMS
    // percentile means WORSE care. It can never be a quality rank.
    if (/_PERCENTILE$/.test(String(m.measureCode))) {
      problems.push(`${at} is a CMS _PERCENTILE field; those are raw-value ranks, not quality ranks, and must never be surfaced`);
    }
  }
  if (problems.length) {
    console.error('\nMEASURE REGISTRY INVALID — refusing to ingest:');
    problems.forEach((p) => console.error(`  - ${p}`));
    process.exit(1);
  }
  return reg;
}

// ---- archive discovery ----------------------------------------------------
function archiveCandidates() {
  const out = [];
  const v2 = path.join(ARCHIVE_ROOT, ARCHIVE_FAMILY);
  if (fs.existsSync(v2)) {
    for (const d of fs.readdirSync(v2).sort()) {
      if (fs.existsSync(path.join(v2, d, 'manifest.json'))) out.push({ key: d, dir: path.join(v2, d), layout: 'v2' });
    }
  }
  return out.sort((a, b) => a.key.localeCompare(b.key));
}

// ---- archive validation ---------------------------------------------------
// Archive V2 only. A legacy pre-V2 manifest records no source, status or
// datasetCount, and reconstructing archive metadata is not this script's job.
function validateArchive(reg, cand) {
  const problems = [];
  const mfPath = path.join(cand.dir, 'manifest.json');
  if (!fs.existsSync(mfPath)) fail(`ARCHIVE INVALID: no manifest.json in ${path.relative(ROOT, cand.dir)}`);

  const rawManifest = fs.readFileSync(mfPath);            // raw bytes, hashed as-is
  const manifestSha256 = sha256(rawManifest);
  let mf;
  try { mf = JSON.parse(rawManifest.toString('utf8')); }
  catch (e) { fail(`ARCHIVE INVALID: manifest.json is not valid JSON (${e.message})`); }

  if (mf.releaseKey !== cand.key) problems.push(`manifest releaseKey "${mf.releaseKey}" does not match archive directory "${cand.key}"`);
  if (!RELEASE_KEY_RE.test(String(mf.releaseKey || ''))) {
    problems.push(`releaseKey "${mf.releaseKey}" is not YYYY-MM-DD; chronological ordering depends on that format`);
  }

  const hospiceCfg = reg.datasets.filter((d) => d.source === ARCHIVE_FAMILY);
  const files = mf.files || {};

  const missingFacts = [];
  if (mf.schemaVersion == null || Number(mf.schemaVersion) < 2) missingFacts.push('schemaVersion >= 2');
  if (mf.source == null) missingFacts.push('source');
  if (mf.status == null) missingFacts.push('status');
  if (mf.datasetCount == null) missingFacts.push('datasetCount');
  for (const k of REQUIRED_FOR_INGEST) {
    if (files[k] && !Array.isArray(files[k].headers)) missingFacts.push(`files.${k}.headers`);
  }
  if (missingFacts.length) {
    problems.push('Archive V2 manifest required for CMS quality ingestion. This archive is missing recorded '
      + `manifest fact(s): ${missingFacts.join(', ')}.\n`
      + '    Re-archive this release with the current archiver:\n'
      + `      node scripts/cms-archive.js --source ${ARCHIVE_FAMILY}\n`
      + '    This script will not infer archive metadata.');
  } else {
    if (mf.source !== ARCHIVE_FAMILY) problems.push(`manifest source is "${mf.source}", expected "${ARCHIVE_FAMILY}"`);
    if (mf.status !== 'complete') problems.push(`manifest status is "${mf.status}", expected "complete"`);
  }

  for (const k of REQUIRED_FOR_INGEST) {
    if (!files[k]) { problems.push(`required dataset "${k}" is absent from the manifest`); continue; }
    if (!fs.existsSync(path.join(cand.dir, `${k}.csv.gz`))) {
      problems.push(`required dataset "${k}" is in the manifest but ${k}.csv.gz is missing on disk`);
    }
  }
  if (problems.length) {
    console.error('\nARCHIVE INVALID — refusing to ingest:');
    problems.forEach((p) => console.error(`  - ${p}`));
    process.exit(1);
  }

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
    if (!cfg) fail(`ARCHIVE INVALID: the tracked registry declares no "${k}" dataset for ${ARCHIVE_FAMILY}`);
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

  if (!mf.capturedAt) fail('ARCHIVE INVALID: manifest has no capturedAt');

  return {
    dir: cand.dir, layout: cand.layout, releaseKey: mf.releaseKey,
    capturedAt: new Date(mf.capturedAt), manifestSha256, datasetCount: mf.datasetCount,
    data
  };
}

// ---- measure-level drift detection ---------------------------------------
// Header equality proves the file's SHAPE is unchanged. It says nothing about
// whether CMS still publishes H_012_02_OBSERVED, or still means by it what it
// meant last release. This closes that gap: every declared code must be present,
// and CMS's own Measure Name for it must match the recorded fact exactly.
function assertMeasuresPresent(mreg, data) {
  const problems = [];
  const index = {};                            // dataset -> code -> Set(names)
  for (const k of REQUIRED_FOR_INGEST) {
    const idx = index[k] = new Map();
    for (const r of data[k]) {
      const code = String(r[COL.code] || '').trim();
      if (!code) continue;
      if (!idx.has(code)) idx.set(code, new Set());
      idx.get(code).add(String(r[COL.name] || '').trim());
    }
  }
  for (const m of mreg.measures) {
    const idx = index[m.dataset];
    const names = idx.get(m.measureCode);
    if (!names) {
      problems.push(`required measure code "${m.measureCode}" is ABSENT from the ${m.dataset} dataset`);
      continue;
    }
    if (names.size !== 1) {
      problems.push(`"${m.measureCode}" carries ${names.size} different CMS Measure Names in one release: ${[...names].map((n) => `"${n}"`).join(', ')}`);
      continue;
    }
    const actual = [...names][0];
    if (actual !== m.cmsMeasureName) {
      problems.push(`CMS renamed or redefined "${m.measureCode}"\n`
        + `      recorded: "${m.cmsMeasureName}"\n`
        + `      archived: "${actual}"\n`
        + '      Review the measure before ingesting: a redefinition can invert what "better" means.');
    }
    if (m.denominatorCode && !idx.has(m.denominatorCode)) {
      problems.push(`"${m.measureCode}" declares denominator code "${m.denominatorCode}", which is ABSENT from the ${m.dataset} dataset`);
    }
  }
  if (problems.length) {
    console.error('\nMEASURE DRIFT — refusing to ingest:');
    problems.forEach((p) => console.error(`  - ${p}`));
    process.exit(1);
  }
  return index;
}

// ---- build intended measurement rows -------------------------------------
// One row per (CCN, surfaced measure), INCLUDING the ones CMS suppressed. A
// suppressed row is the record that CMS published nothing, which is what keeps
// "withheld" distinguishable from "never ingested".
function buildMeasurements(mreg, data) {
  const rows = new Map();                      // `${ccn}|${code}` -> row
  const denominators = new Map();              // `${ccn}|${code}` -> number|null
  const conflicts = [];
  let identicalDupes = 0;
  let suppressed = 0;
  const byMeasure = new Map();                 // code -> { total, withValue }

  const byDataset = new Map();
  const denomOwner = new Map();                // `${dataset}|${denomCode}` -> measureCode
  for (const m of mreg.measures) {
    if (!byDataset.has(m.dataset)) byDataset.set(m.dataset, new Map());
    byDataset.get(m.dataset).set(m.measureCode, m);
    if (m.denominatorCode) denomOwner.set(`${m.dataset}|${m.denominatorCode}`, m.measureCode);
    byMeasure.set(m.measureCode, { total: 0, withValue: 0 });
  }

  for (const dataset of REQUIRED_FOR_INGEST) {
    const wanted = byDataset.get(dataset) || new Map();
    const periodCol = PERIOD_COL[dataset];
    for (const r of data[dataset]) {
      const ccn = String(r[COL.ccn] || '').trim();
      const code = String(r[COL.code] || '').trim();
      if (!ccn || !code) continue;

      const owner = denomOwner.get(`${dataset}|${code}`);
      if (owner) {
        // A companion sample-size cell. Stored on the measure's own row, not as
        // a measurement in its own right.
        denominators.set(`${ccn}|${owner}`, parseDenominatorCell(r[COL.score], `${ccn}/${code}`));
        continue;
      }

      const m = wanted.get(code);
      if (!m) continue;                        // an undeclared CMS measure: not ours to store

      const label = `${ccn}/${code}`;
      // CAHPS publishes the summary rating in "Star Rating"; everything else in
      // "Score". The registry names the value column, so this is a recorded
      // decision rather than a hard-coded special case for one measure.
      const valueColumn = m.valueColumn === COL.star ? COL.star : COL.score;
      let parsed;
      let starRating = null;
      if (valueColumn === COL.star) {
        const stars = parseStarRatingCell(r[COL.star], label);
        starRating = stars;
        parsed = {
          valueRaw: String(r[COL.star] == null ? '' : r[COL.star]),
          valueNumeric: stars,
          suppressed: stars === null,
          footnoteCodes: []
        };
      } else {
        parsed = parseScoreCell(r[COL.score], label);
      }

      const footnotes = [...new Set([...parsed.footnoteCodes, ...parseFootnoteCell(r[COL.footnote], label)])].sort();
      const period = parsePeriodCell(r[periodCol], label);

      const rec = {
        ccn,
        measureCode: code,
        valueNumeric: parsed.valueNumeric,
        valueRaw: parsed.valueRaw,
        suppressed: parsed.suppressed,
        footnoteCodes: footnotes,
        starRating,
        periodStart: period ? period.start : null,
        periodEnd: period ? period.end : null
      };

      const key = `${ccn}|${code}`;
      const prev = rows.get(key);
      if (prev) {
        if (JSON.stringify(prev) === JSON.stringify(rec)) { identicalDupes++; continue; }
        conflicts.push(label);
        continue;
      }
      rows.set(key, rec);
      const stat = byMeasure.get(code);
      stat.total++;
      if (!rec.suppressed) stat.withValue++; else suppressed++;
    }
  }

  // Attach denominators once every row exists, so ordering within the file
  // cannot decide whether a sample size is captured.
  for (const [key, row] of rows) {
    if (denominators.has(key)) row.denominator = denominators.get(key);
    else row.denominator = null;
  }

  return { rows, conflicts: [...new Set(conflicts)], identicalDupes, suppressed, byMeasure };
}

// ---- production guard -----------------------------------------------------
function assertTargetAllowed(url, action, facts, token) {
  const verb = `Refusing to ${action}`;
  if (!url) fail(`${verb}: DATABASE_URL is not set.`);
  const target = guard.classifyTarget(url);

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
    if (token == null) {
      fail(`${verb}: DATABASE_URL points at the production database.\n`
        + '  Production is refused by default. A deliberate one-time QUALITY ingestion\n'
        + `  of a specific release requires --production-authorization <64-hex>, scoped\n`
        + `  to operation=${AUTHORIZATION_OPERATION}, source=${facts.dbSource},\n`
        + `  releaseKey=${facts.releaseKey} and that release's exact manifestSha256.\n`
        + '  A facility-ingestion token does NOT authorize this step.\n'
        + '  Compute it from the validated archive with:\n'
        + `    node scripts/import-cms-hospice-quality.js --release ${facts.releaseKey} --print-production-authorization\n`
        + '  Authorization permits the connection only. Writing still requires --write.\n'
        + '  ZERO writes.');
    }
    // Never echo the expected token: a failed attempt must not hand the operator
    // the value that would have succeeded.
    if (!guard.tokenMatches(token, guard.authorizationToken(facts))) {
      fail(`${verb}: the supplied --production-authorization does not match this release.\n`
        + `  It must be derived from operation=${AUTHORIZATION_OPERATION}, source=${facts.dbSource},\n`
        + `  releaseKey=${facts.releaseKey} and this archive's exact manifestSha256. A token\n`
        + '  for any other operation, release, manifest or source is rejected. ZERO writes.');
    }
    console.log('');
    console.log('!'.repeat(72));
    console.log(`!  PRODUCTION TARGET AUTHORIZED for ${facts.dbSource} QUALITY release ${facts.releaseKey}`);
    console.log('!  Authorization is scoped to this operation, release and manifest only.');
    console.log(`!  Mode: ${action === 'write' ? 'WRITE (--write supplied)' : 'READ-ONLY PLANNING (no --write)'}`);
    console.log('!'.repeat(72));
  }
}

const pad = (s, n) => String(s).padEnd(n);

(async () => {
  const reg = loadJson(REGISTRY_PATH);
  const dbSource = (reg.sources || {})[ARCHIVE_FAMILY] && reg.sources[ARCHIVE_FAMILY].externalIdentitySource;
  if (!dbSource) fail(`registry has no sources["${ARCHIVE_FAMILY}"].externalIdentitySource mapping`);
  const mreg = loadMeasureRegistry();
  if (mreg.source !== dbSource) {
    fail(`measure registry source "${mreg.source}" does not match the dataset registry mapping "${dbSource}"`);
  }

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
    console.log('No --release given; selecting the LATEST local archive deterministically.');
  }

  const arc = validateArchive(reg, cand);
  assertMeasuresPresent(mreg, arc.data);

  let built;
  try {
    built = buildMeasurements(mreg, arc.data);
  } catch (e) {
    if (e instanceof QualityParseError) {
      fail(`CELL PARSE FAILURE — refusing to ingest:\n  ${e.message}\n`
        + '  Every cell must parse into a documented CMS shape. Nothing was written.');
    }
    throw e;
  }
  const providerRowCount = arc.data.provider.length;
  const cahpsRowCount = arc.data.cahps_provider.length;
  arc.data.provider = null;          // release the parsed arrays before any
  arc.data.cahps_provider = null;    // database work begins

  const releaseFacts = {
    operation: AUTHORIZATION_OPERATION, dbSource,
    releaseKey: arc.releaseKey, manifestSha256: arc.manifestSha256
  };

  console.log('');
  console.log('='.repeat(78));
  console.log('ARCHIVE');
  console.log('='.repeat(78));
  console.log(`  archive path      : ${path.relative(ROOT, arc.dir)}  (${arc.layout} layout)`);
  console.log(`  source family     : ${ARCHIVE_FAMILY}`);
  console.log(`  mapped DB source  : ${dbSource}`);
  console.log(`  releaseKey        : ${arc.releaseKey}`);
  console.log(`  capturedAt        : ${arc.capturedAt.toISOString()}`);
  console.log(`  manifest sha256   : ${arc.manifestSha256}`);
  console.log(`  datasets read     : ${REQUIRED_FOR_INGEST.join(', ')}`);
  console.log(`  provider rows     : ${providerRowCount.toLocaleString()}`);
  console.log(`  cahps rows        : ${cahpsRowCount.toLocaleString()}`);

  console.log('');
  console.log('='.repeat(78));
  console.log('MEASURES  (direction is read from the registry, never inferred)');
  console.log('='.repeat(78));
  for (const m of mreg.measures) {
    const st = built.byMeasure.get(m.measureCode);
    const availPct = st.total ? ((st.withValue / st.total) * 100).toFixed(1) : '0.0';
    console.log(`  ${pad(m.measureCode, 20)} ${pad(m.direction, 14)} ${pad(m.dimension, 20)} `
      + `published ${String(st.withValue).padStart(6)}/${String(st.total).padStart(6)} (${availPct}%)`);
  }

  const report = {
    generatedAt: new Date().toISOString(),
    operation: AUTHORIZATION_OPERATION,
    archive: { dir: path.relative(ROOT, arc.dir), releaseKey: arc.releaseKey, manifestSha256: arc.manifestSha256 },
    source: dbSource,
    datasets: { provider: providerRowCount, cahps_provider: cahpsRowCount },
    intended: {
      definitions: mreg.measures.length,
      measurements: built.rows.size,
      suppressed: built.suppressed,
      identicalDuplicateCells: built.identicalDupes,
      conflictingCells: built.conflicts.length
    },
    perMeasure: Object.fromEntries([...built.byMeasure].map(([k, v]) => [k, v])),
    plan: null
  };

  if (built.conflicts.length) {
    console.log('');
    fail(`CELL CONFLICT: ${built.conflicts.length} (CCN, measure) pair(s) appear more than once with different values, `
      + `e.g. ${built.conflicts.slice(0, 3).join(', ')}.\n`
      + '  CMS publishes one value per facility per measure per release, so this is\n'
      + '  unexplained. Refusing to choose. ZERO writes.');
  }

  if (opts.printAuthorization) {
    console.log('');
    console.log('PRODUCTION AUTHORIZATION TOKEN (quality ingestion of this release only)');
    console.log(`  operation      : ${AUTHORIZATION_OPERATION}`);
    console.log(`  source         : ${dbSource}`);
    console.log(`  releaseKey     : ${arc.releaseKey}`);
    console.log(`  manifestSha256 : ${arc.manifestSha256}`);
    console.log(`  token          : ${guard.authorizationToken(releaseFacts)}`);
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
    // ---- preconditions, read-only first ----
    const release = await prisma.cmsRelease.findUnique({
      where: { source_releaseKey: { source: dbSource, releaseKey: arc.releaseKey } } });
    if (!release) {
      fail(`RELEASE NOT INGESTED: no ${dbSource} release "${arc.releaseKey}" exists.\n`
        + '  Quality measurements are foreign-keyed to CmsFacility and CmsRelease, so the\n'
        + '  facility roster for this release must be loaded first:\n'
        + `    node scripts/import-cms-hospice-data.js --release ${arc.releaseKey} --write\n`
        + '  This script never creates a release row. ZERO writes.');
    }
    if (release.manifestSha256 == null) {
      fail(`RELEASE UNVERIFIABLE: the stored ${arc.releaseKey} release has a NULL manifestSha256,\n`
        + '  so this archive cannot be proven to be the one the facilities came from. ZERO writes.');
    }
    if (release.manifestSha256 !== arc.manifestSha256) {
      fail(`ARCHIVE MISMATCH: the stored ${arc.releaseKey} release was ingested from a DIFFERENT archive.\n`
        + `    stored manifest : ${release.manifestSha256}\n`
        + `    this archive    : ${arc.manifestSha256}\n`
        + '  Loading quality data from one archive onto facilities from another would\n'
        + '  attribute measurements to the wrong roster. ZERO writes.');
    }

    // Chronology is decided by the LATEST ingested release for this source, never
    // by whether the requested release happens to exist. Runs before the plan is
    // printed, so a DB-backed dry run refuses an out-of-order release too.
    const latest = await prisma.cmsRelease.findFirst({ where: { source: dbSource }, orderBy: { releaseKey: 'desc' } });
    if (latest && latest.releaseKey > arc.releaseKey) {
      console.log('');
      fail(`CHRONOLOGY VIOLATION: release ${arc.releaseKey} is OLDER than the latest ingested `
        + `${dbSource} release ${latest.releaseKey}.\n`
        + '  Quality measurements are per-release history, and the provider-facing module\n'
        + '  reads the NEWEST release that has measurements. Backfilling an older release\n'
        + '  after a newer one would leave the two out of step. ZERO writes.');
    }

    // ---- classify measurements, set-based ----
    // Streamed to the server in chunks and classified by a join against unnest(),
    // so peak JS memory is one chunk regardless of table size. Not N+1: ~14
    // queries for ~67k cells.
    const CLASSIFY_CHUNK = 5000;
    let mCreate = 0, mUpdate = 0, mUnchanged = 0, mOrphan = 0;
    const orphanCcns = new Set();
    {
      const it = built.rows.values();
      let ccns = [], codes = [], vals = [], done = false;
      const flush = async () => {
        if (!ccns.length) return;
        const [row] = await prisma.$queryRawUnsafe(
          `SELECT
             count(*) FILTER (WHERE f.id IS NULL)::int                                     AS orphans,
             count(*) FILTER (WHERE f.id IS NOT NULL AND e.id IS NULL)::int                AS creates,
             count(*) FILTER (WHERE e.id IS NOT NULL
                                AND (e."valueRaw" IS DISTINCT FROM t.raw))::int            AS updates,
             count(*) FILTER (WHERE e.id IS NOT NULL
                                AND e."valueRaw" = t.raw)::int                             AS unchanged
           FROM unnest($1::text[], $2::text[], $3::text[]) AS t(ccn, code, raw)
           LEFT JOIN "CmsFacility" f
             ON f.source = $4::text AND f.ccn = t.ccn
           LEFT JOIN "CmsFacilityMeasure" e
             ON e."facilityId" = f.id AND e."measureCode" = t.code AND e."releaseId" = $5::text`,
          ccns, codes, vals, dbSource, release.id);
        mOrphan += row.orphans; mCreate += row.creates; mUpdate += row.updates; mUnchanged += row.unchanged;
        ccns = []; codes = []; vals = [];
      };
      while (!done) {
        const n = it.next();
        if (n.done) done = true;
        else { ccns.push(n.value.ccn); codes.push(n.value.measureCode); vals.push(n.value.valueRaw); }
        if (done || ccns.length >= CLASSIFY_CHUNK) await flush();
      }
    }
    if (mOrphan) {
      // A CCN CMS publishes quality for but that is not in the ingested roster.
      // Reported, never invented: there is no facility row to attach it to.
      const knownCcns = new Set((await prisma.cmsFacility.findMany({
        where: { source: dbSource }, select: { ccn: true } })).map((f) => f.ccn));
      for (const r of built.rows.values()) if (!knownCcns.has(r.ccn)) orphanCcns.add(r.ccn);
    }

    const defsExisting = await prisma.cmsMeasureDefinition.count({ where: { source: dbSource } });

    console.log('');
    console.log('='.repeat(78));
    console.log(`PLAN  (${opts.write ? 'WRITE MODE' : 'DRY RUN — ZERO WRITES'})`);
    console.log('='.repeat(78));
    console.log(`  release           : EXISTS   ${dbSource} / ${arc.releaseKey}   (manifest verified)`);
    console.log(`  chronology        : ${latest && latest.releaseKey === arc.releaseKey ? 'newest ingested release — OK' : `later than ${latest ? latest.releaseKey : 'none'} — OK`}`);
    console.log(`  definitions       : UPSERT ${mreg.measures.length}   (currently stored ${defsExisting})`);
    console.log(`  measurements      : CREATE ${mCreate}   UPDATE ${mUpdate}   UNCHANGED ${mUnchanged}`);
    console.log(`  suppressed cells  : ${built.suppressed} of ${built.rows.size} stored as suppressed=true (never zero)`);
    console.log(`  orphan CCNs       : ${orphanCcns.size} CCN(s) / ${mOrphan} cell(s) published by CMS but absent from the ingested roster — SKIPPED`);

    report.plan = {
      release: 'EXISTS',
      definitions: { upsert: mreg.measures.length, existing: defsExisting },
      measurements: { create: mCreate, update: mUpdate, unchanged: mUnchanged, orphanCells: mOrphan, orphanCcns: orphanCcns.size },
      suppressed: built.suppressed
    };
    if (opts.json) { fs.writeFileSync(opts.json, JSON.stringify(report, null, 2) + '\n'); console.log(`\n  wrote ${opts.json}`); }

    if (!opts.write) {
      console.log('');
      console.log('DRY RUN — nothing was written. Re-run with --write to apply.');
      return;
    }
    if (mCreate === 0 && mUpdate === 0 && defsExisting === mreg.measures.length) {
      console.log('\nAlready ingested and unchanged. No transaction opened.');
      return;
    }

    console.log('\n' + '*'.repeat(72));
    console.log(`*  WRITE MODE ACTIVE — ingesting ${dbSource} QUALITY release ${arc.releaseKey}`);
    console.log('*'.repeat(72));

    const t0 = Date.now();
    const toWrite = [...built.rows.values()].filter((r) => !orphanCcns.has(r.ccn));
    await prisma.$transaction(async (tx) => {
      // FIRST statement: serialise quality ingestion per source, on a lock name
      // distinct from the facility importer's so the two never block each other
      // while still excluding a second concurrent quality run.
      await tx.$executeRawUnsafe('SELECT pg_advisory_xact_lock(hashtext($1))', `cms-quality-ingest:${dbSource}`);

      // Re-check preconditions AFTER the lock is held.
      const rel = await tx.cmsRelease.findUnique({
        where: { source_releaseKey: { source: dbSource, releaseKey: arc.releaseKey } } });
      if (!rel) throw new Error('the release disappeared inside the transaction');
      if (rel.manifestSha256 !== arc.manifestSha256) throw new Error('manifest changed inside the transaction');
      const newest = await tx.cmsRelease.findFirst({ where: { source: dbSource }, orderBy: { releaseKey: 'desc' } });
      if (newest && newest.releaseKey > arc.releaseKey) {
        throw new Error(`chronology violation detected inside the transaction: ${arc.releaseKey} is older than ${newest.releaseKey}`);
      }

      // Definitions FIRST: CmsFacilityMeasure has a foreign key to them, so an
      // undefined measure code cannot be inserted at all.
      for (const m of mreg.measures) {
        await tx.$executeRawUnsafe(
          `INSERT INTO "CmsMeasureDefinition"
             ("id","source","measureCode","cmsMeasureName","shortLabel","dimension","family","valueKind",
              "direction","scaleMin","scaleMax","decimals","unitLabel","denominatorCode","surfaced",
              "createdAt","updatedAt")
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,NOW(),NOW())
           ON CONFLICT ("source","measureCode") DO UPDATE SET
             "cmsMeasureName"=EXCLUDED."cmsMeasureName", "shortLabel"=EXCLUDED."shortLabel",
             "dimension"=EXCLUDED."dimension", "family"=EXCLUDED."family",
             "valueKind"=EXCLUDED."valueKind", "direction"=EXCLUDED."direction",
             "scaleMin"=EXCLUDED."scaleMin", "scaleMax"=EXCLUDED."scaleMax",
             "decimals"=EXCLUDED."decimals", "unitLabel"=EXCLUDED."unitLabel",
             "denominatorCode"=EXCLUDED."denominatorCode", "surfaced"=EXCLUDED."surfaced",
             "updatedAt"=NOW()`,
          crypto.randomUUID(), dbSource, m.measureCode, m.cmsMeasureName, m.shortLabel, m.dimension,
          m.family, m.valueKind, m.direction,
          m.scaleMin == null ? null : Number(m.scaleMin), m.scaleMax == null ? null : Number(m.scaleMax),
          Number(m.decimals), m.unitLabel == null ? null : String(m.unitLabel),
          m.denominatorCode == null ? null : String(m.denominatorCode), m.surfaced === true);
      }

      const idRows = await tx.cmsFacility.findMany({ where: { source: dbSource }, select: { id: true, ccn: true } });
      const ccnToId = new Map(idRows.map((r) => [r.ccn, r.id]));

      const CHUNK = 1000;
      for (let i = 0; i < toWrite.length; i += CHUNK) {
        const chunk = toWrite.slice(i, i + CHUNK);
        const params = []; const tuples = [];
        for (const r of chunk) {
          const b = params.length;
          // Periods are passed as plain YYYY-MM-DD STRINGS, never JS Dates: the pg
          // driver serialises a Date in LOCAL time, so `::date` truncates it to the
          // previous day at any negative UTC offset - a silent off-by-one.
          params.push(crypto.randomUUID(), ccnToId.get(r.ccn), dbSource, r.measureCode, rel.id,
            r.valueNumeric, r.valueRaw, r.suppressed, r.footnoteCodes,
            r.denominator, r.starRating, r.periodStart, r.periodEnd);
          tuples.push(`($${b+1},$${b+2},$${b+3},$${b+4},$${b+5},$${b+6},$${b+7},$${b+8},$${b+9}::text[],`
            + `$${b+10},$${b+11},$${b+12}::date,$${b+13}::date,NOW(),NOW())`);
        }
        await tx.$executeRawUnsafe(
          `INSERT INTO "CmsFacilityMeasure"
             ("id","facilityId","source","measureCode","releaseId","valueNumeric","valueRaw","suppressed",
              "footnoteCodes","denominator","starRating","periodStart","periodEnd","createdAt","updatedAt")
           VALUES ${tuples.join(',')}
           ON CONFLICT ("facilityId","measureCode","releaseId") DO UPDATE SET
             "valueNumeric"=EXCLUDED."valueNumeric", "valueRaw"=EXCLUDED."valueRaw",
             "suppressed"=EXCLUDED."suppressed", "footnoteCodes"=EXCLUDED."footnoteCodes",
             "denominator"=EXCLUDED."denominator", "starRating"=EXCLUDED."starRating",
             "periodStart"=EXCLUDED."periodStart", "periodEnd"=EXCLUDED."periodEnd",
             "updatedAt"=NOW()`, ...params);
      }

      // Postconditions inside the transaction.
      const nd = await tx.cmsMeasureDefinition.count({ where: { source: dbSource } });
      if (nd < mreg.measures.length) throw new Error(`postcondition: ${nd} definitions stored, expected at least ${mreg.measures.length}`);
      const nm = await tx.cmsFacilityMeasure.count({ where: { source: dbSource, releaseId: rel.id } });
      if (nm !== toWrite.length) throw new Error(`postcondition: ${nm} measurements carry this release, expected ${toWrite.length}`);
      // Suppression must survive the round trip: a suppressed row with a number
      // in it would mean a sentinel had been coerced.
      const bad = await tx.cmsFacilityMeasure.count({
        where: { source: dbSource, releaseId: rel.id, suppressed: true, valueNumeric: { not: null } } });
      if (bad) throw new Error(`postcondition: ${bad} suppressed measurement(s) carry a numeric value`);
    }, { timeout: 600000, maxWait: 60000 });

    const totals = {
      definitions: await prisma.cmsMeasureDefinition.count({ where: { source: dbSource } }),
      measurements: await prisma.cmsFacilityMeasure.count({ where: { source: dbSource } }),
      suppressed: await prisma.cmsFacilityMeasure.count({ where: { source: dbSource, suppressed: true } })
    };
    console.log(`\nINGESTED quality for release ${arc.releaseKey} in one transaction (${((Date.now() - t0) / 1000).toFixed(1)}s).`);
    console.log(`  CmsMeasureDefinition ${totals.definitions}   CmsFacilityMeasure ${totals.measurements}`
      + `   (of which suppressed ${totals.suppressed})`);
  } finally {
    if (typeof prisma !== 'undefined') await prisma.$disconnect().catch(() => {});
  }
})().catch((e) => {
  const detail = [e && e.message, e && e.code && `code ${e.code}`].filter(Boolean).join(' | ') || String(e);
  console.error(`\nQUALITY INGESTION FAILED — transaction rolled back, ZERO rows written.\n  ${guard.scrub(detail).split('\n').slice(-4).join('\n  ')}`);
  process.exit(1);
});
