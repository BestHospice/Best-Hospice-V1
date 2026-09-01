#!/usr/bin/env node
/**
 * Archive one CMS Provider Data Catalog release, per source family.
 *
 * CMS overwrites its files in place, so any measure comparing one release to the
 * next can only ever use history we kept at the time. A missed quarter is
 * unrecoverable. This is the cheapest possible insurance.
 *
 * Two source families are archived independently so a failure in one is
 * attributable and never reported as success for the other:
 *
 *   hospice       6 datasets, ~135 MB raw / ~5.5 MB gzipped
 *   home-health   5 datasets, ~23 MB raw / ~3.2 MB gzipped
 *
 * These are ARCHIVE FAMILY names. They are a different namespace from
 * ProviderExternalIdentity.source ("cms_hospice", "cms_home_health") and must
 * never be joined to it by string equality. The mapping lives in the registry
 * under sources[]. This archiver knows nothing about identities.
 *
 * Read-only with respect to CMS and to the site. Writes one directory per
 * release and refuses to overwrite an existing one.
 *
 * Archive immutability is defined by CMS metadata: once a releaseKey is
 * captured it is never re-downloaded. A changed sourceUrl or modified date for
 * a known key is detected and fails. Upstream byte changes under IDENTICAL
 * metadata are not detected - see docs/cms-data-pipeline.md.
 *
 *   node scripts/cms-archive.js --source hospice
 *   node scripts/cms-archive.js --source home-health
 *   node scripts/cms-archive.js --all
 *   node scripts/cms-archive.js --source hospice --print-key
 *   node scripts/cms-archive.js --source hospice --dry-run
 *   node scripts/cms-archive.js --list
 *   node scripts/cms-archive.js --source home-health --probe   bootstrap headers only
 *
 * CMS_ARCHIVE_DIR overrides where archives are written.
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const https = require('https');

const ROOT = path.join(__dirname, '..');
const ARCHIVE = process.env.CMS_ARCHIVE_DIR
  ? path.resolve(process.env.CMS_ARCHIVE_DIR)
  : path.join(ROOT, 'reports', 'cms-archive');
const CATALOG = 'https://data.cms.gov/provider-data/api/1/metastore/schemas/dataset/items?show-reference-ids=false';
const REGISTRY_PATH = process.env.CMS_REGISTRY_PATH
  ? path.resolve(process.env.CMS_REGISTRY_PATH)
  : path.join(ROOT, 'data', 'cms-dataset-registry.json');

// Existing hospice releases live directly under reports/cms-archive/<key>/.
// New releases are written under <source>/<key>/. Legacy directories are still
// read and still count as "already archived" so a refactor cannot cause a
// 135 MB re-download or a duplicate capture.
const LEGACY_SOURCE = 'hospice';
const SOURCE_DIRS = { hospice: 'hospice', 'home-health': 'home-health' };

const loadRegistry = () => JSON.parse(fs.readFileSync(REGISTRY_PATH, 'utf8'));
const datasetsFor = (reg, source) => reg.datasets.filter((d) => d.source === source);

const get = (url) => new Promise((resolve, reject) => {
  https.get(url, { headers: { 'User-Agent': 'BestHospice-archive/2.0' } }, (res) => {
    if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
      res.resume();
      return get(res.headers.location).then(resolve, reject);
    }
    if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode} for ${url}`)); }
    const chunks = [];
    res.on('data', (c) => chunks.push(c));
    res.on('end', () => resolve(Buffer.concat(chunks)));
  }).on('error', reject);
});

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

// ---- CSV header + row counting -------------------------------------------
// Quote-aware, because CMS ships embedded commas and newlines. Values are never
// coerced: a CCN like "027001" stays the string it was published as.
function readHeader(text) {
  let cur = '', q = false;
  const cols = [];
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { cur += '"'; i++; } else q = false; } else cur += c; }
    else if (c === '"') q = true;
    else if (c === ',') { cols.push(cur); cur = ''; }
    else if (c === '\n' || c === '\r') { cols.push(cur); return cols; }
    else cur += c;
  }
  cols.push(cur);
  return cols;
}

function countDataRows(text) {
  let n = 0, q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') i++; else q = false; } }
    else if (c === '"') q = true;
    else if (c === '\n') n++;
  }
  // last line may lack a trailing newline
  if (text.length && text[text.length - 1] !== '\n') n++;
  return Math.max(0, n - 1); // minus the header
}

// ---- schema drift ---------------------------------------------------------
// Fail-closed by default. New columns are a schema change like any other: CMS
// adding a field silently is exactly the event this exists to catch.
function validateHeaders(cfg, actual) {
  const expected = cfg.expectedHeaders || [];
  const problems = [];

  if (!actual.length || actual.every((h) => h.trim() === '')) {
    problems.push({ kind: 'EMPTY_HEADER', detail: 'CSV header row is empty' });
    return { ok: false, problems, expected, actual, missing: expected, unexpected: [] };
  }
  const blank = actual.filter((h) => h.trim() === '').length;
  if (blank) problems.push({ kind: 'MALFORMED_HEADER', detail: `${blank} blank column name(s)` });

  const seen = new Map();
  const dupes = [];
  for (const h of actual) {
    if (seen.has(h)) { if (!dupes.includes(h)) dupes.push(h); }
    seen.set(h, true);
  }
  if (dupes.length) problems.push({ kind: 'DUPLICATE_COLUMNS', detail: dupes.join(', ') });

  const eSet = new Set(expected), aSet = new Set(actual);
  const missing = expected.filter((h) => !aSet.has(h));
  const unexpected = actual.filter((h) => !eSet.has(h));
  if (missing.length) problems.push({ kind: 'MISSING_COLUMNS', detail: missing.join(', ') });
  if (unexpected.length) problems.push({ kind: 'UNEXPECTED_COLUMNS', detail: unexpected.join(', ') });
  // A rename shows up as one missing + one unexpected; name it so the operator
  // does not have to infer it.
  if (missing.length && unexpected.length) {
    problems.push({ kind: 'POSSIBLE_RENAME', detail: `${missing.join(', ')} -> ${unexpected.join(', ')}` });
  }
  if (!missing.length && !unexpected.length && expected.length === actual.length) {
    const orderChanged = expected.some((h, i) => actual[i] !== h);
    if (orderChanged) problems.push({ kind: 'COLUMN_ORDER_CHANGED', detail: 'same columns, different order' });
  }
  return { ok: problems.length === 0, problems, expected, actual, missing, unexpected };
}

function driftError(cfg, result) {
  const lines = [
    `SCHEMA DRIFT — refusing to archive.`,
    `  source        : ${cfg.source}`,
    `  logicalKey    : ${cfg.logicalKey}`,
    `  datasetId     : ${cfg.resolvedId || cfg.datasetId || '(pattern-resolved)'}`,
    `  expected (${result.expected.length}): ${result.expected.join(' | ')}`,
    `  actual   (${result.actual.length}): ${result.actual.join(' | ')}`,
    `  missing       : ${result.missing.length ? result.missing.join(', ') : '(none)'}`,
    `  unexpected    : ${result.unexpected.length ? result.unexpected.join(', ') : '(none)'}`
  ];
  for (const p of result.problems) lines.push(`  ${p.kind}: ${p.detail}`);
  lines.push('  Review the change deliberately, then update data/cms-dataset-registry.json.');
  return new Error(lines.join('\n'));
}

// ---- resolution -----------------------------------------------------------
async function resolveSource(reg, source) {
  const items = JSON.parse((await get(CATALOG)).toString('utf8'));
  return resolveFromItems(reg, source, items);
}

// Pure: takes an already-fetched catalog. Kept separate so resolution rules -
// especially the exactly-one-match requirement for period-versioned titles -
// are testable without touching the network.
function resolveFromItems(reg, source, items) {
  const byId = new Map(items.map((i) => [i.identifier, i]));
  const out = [];
  for (const cfg of datasetsFor(reg, source)) {
    let item = null;
    if (cfg.datasetId) {
      item = byId.get(cfg.datasetId) || null;
      if (!item && cfg.required !== false) {
        throw new Error(`dataset ${cfg.datasetId} (${source}/${cfg.logicalKey}) is no longer in the CMS catalog`);
      }
    } else if (cfg.titlePattern) {
      // The reporting period is encoded in the title and the identifier is not
      // proven stable across period rolls, so resolve by pattern and demand
      // exactly one match. Never silently take the first.
      const re = new RegExp(cfg.titlePattern);
      const hits = items.filter((i) => re.test(i.title || ''));
      if (hits.length !== 1) {
        const msg = `${source}/${cfg.logicalKey}: title pattern matched ${hits.length} dataset(s), expected exactly 1`
          + (hits.length ? `\n  matches: ${hits.map((h) => `${h.identifier} "${h.title}"`).join('\n           ')}` : '')
          + `\n  pattern: ${cfg.titlePattern}`;
        if (cfg.required === false) { out.push({ cfg, skipped: msg }); continue; }
        throw new Error(msg);
      }
      item = hits[0];
    }
    if (!item) { out.push({ cfg, skipped: `${cfg.datasetId} not in catalog (optional)` }); continue; }
    const dist = (item.distribution || [])[0] || {};
    const url = (dist.data && dist.data.downloadURL) || dist.downloadURL;
    if (!url) {
      const msg = `dataset ${item.identifier} (${source}/${cfg.logicalKey}) has no download URL`;
      if (cfg.required === false) { out.push({ cfg, skipped: msg }); continue; }
      throw new Error(msg);
    }
    out.push({ cfg, resolvedId: item.identifier, title: item.title, modified: item.modified, url });
  }
  return out;
}

const releaseKeyOf = (resolved) =>
  resolved.filter((r) => !r.skipped).map((r) => r.modified).filter(Boolean).sort().pop();

// ---- release directories (backward compatible) ----------------------------
function releaseDir(source, key) { return path.join(ARCHIVE, SOURCE_DIRS[source], key); }
function legacyDir(source, key) { return source === LEGACY_SOURCE ? path.join(ARCHIVE, key) : null; }
function existingDir(source, key) {
  const cur = releaseDir(source, key);
  if (fs.existsSync(cur)) return cur;
  const leg = legacyDir(source, key);
  return leg && fs.existsSync(leg) ? leg : null;
}

function list() {
  if (!fs.existsSync(ARCHIVE)) return console.log('no archives yet');
  const rows = [];
  const labelFor = (s, layout) => (layout === 'legacy' ? `${s} (legacy layout)` : s);
  const scan = (dir, source, layout) => {
    if (!fs.existsSync(dir)) return;
    for (const d of fs.readdirSync(dir).sort()) {
      const full = path.join(dir, d);
      if (!fs.statSync(full).isDirectory()) continue;
      if (layout === 'legacy' && Object.values(SOURCE_DIRS).includes(d)) continue; // source dirs, not releases
      const mf = path.join(full, 'manifest.json');
      let note = '';
      if (fs.existsSync(mf)) {
        const m = JSON.parse(fs.readFileSync(mf, 'utf8'));
        const files = m.files || {};
        const mb = Object.values(files).reduce((a, f) => a + (f.gzipBytes || 0), 0) / 1048576;
        note = `${Object.keys(files).length} datasets, ${mb.toFixed(1)} MB gz, ${m.status || 'complete'}`;
      }
      rows.push({ source: labelFor(source, layout), key: d, layout, note });
    }
  };
  scan(ARCHIVE, LEGACY_SOURCE, 'legacy');
  for (const [src, dirname] of Object.entries(SOURCE_DIRS)) scan(path.join(ARCHIVE, dirname), src, 'current');
  if (!rows.length) return console.log('no archives yet');
  console.log(`${rows.length} archived release(s):`);
  for (const r of rows) console.log(`  ${r.source.padEnd(24)} ${r.key.padEnd(12)} ${r.note}`);
}

// ---- main per-source archive ----------------------------------------------
async function archiveSource(reg, source, args) {
  const probe = args.includes('--probe');
  const dryRun = args.includes('--dry-run');
  console.log(`\n=== ${source} ===`);
  console.log('resolving from the CMS Provider Data Catalog...');
  const resolved = await resolveSource(reg, source);
  const active = resolved.filter((r) => !r.skipped);
  const skipped = resolved.filter((r) => r.skipped);
  const key = releaseKeyOf(resolved);
  if (!key) throw new Error(`${source}: no dataset resolved, cannot determine a release key`);
  console.log(`  release key: ${key}`);
  for (const r of active) console.log(`  ${r.cfg.logicalKey.padEnd(18)} ${r.resolvedId.padEnd(11)} modified ${r.modified}`);
  for (const r of skipped) console.log(`  ${r.cfg.logicalKey.padEnd(18)} SKIPPED — ${String(r.skipped).split('\n')[0]}`);

  if (args.includes('--print-key')) { console.log(key); return { source, key, status: 'key-only' }; }

  const already = existingDir(source, key);
  if (already && !probe) {
    // Known releases are never re-downloaded (Option A: archive immutability is
    // defined by CMS metadata). We therefore detect a changed sourceUrl or
    // modified date for an already-archived key, but we do NOT and cannot detect
    // CMS serving different bytes under identical metadata - that would require
    // re-fetching 135 MB every run to compare. sha256 protects the bytes we
    // captured and the integrity of first capture, nothing upstream after that.
    const mf = path.join(already, 'manifest.json');
    if (fs.existsSync(mf)) {
      const prev = JSON.parse(fs.readFileSync(mf, 'utf8'));
      const drift = [];
      for (const r of active) {
        const p = (prev.files || {})[r.cfg.logicalKey];
        if (!p) continue;
        if (p.sourceUrl && p.sourceUrl !== r.url) drift.push(`${r.cfg.logicalKey}: sourceUrl changed`);
        if (p.modified && p.modified !== r.modified) drift.push(`${r.cfg.logicalKey}: modified ${p.modified} -> ${r.modified}`);
      }
      if (drift.length) {
        throw new Error(`${source}: release ${key} is already archived but CMS now reports different metadata:\n  `
          + drift.join('\n  ') + `\n  Refusing to touch the existing archive. Investigate before re-archiving.`);
      }
    }
    console.log(`  release ${key} is already archived at ${path.relative(ROOT, already)} — nothing to do.`);
    return { source, key, status: 'already-archived', datasets: 0 };
  }

  const dir = releaseDir(source, key);
  if (dryRun) {
    console.log(`  --dry-run: would create ${path.relative(ROOT, dir)} and download ${active.length} dataset(s).`);
    return { source, key, status: 'dry-run', datasets: active.length };
  }

  if (!probe) fs.mkdirSync(dir, { recursive: true });
  const files = {};
  const probed = [];
  let totalGz = 0;
  for (const r of active) {
    process.stdout.write(`  downloading ${r.cfg.logicalKey}... `);
    const raw = await get(r.url);
    const text = raw.toString('utf8');
    const headers = readHeader(text);
    const rowCount = countDataRows(text);
    console.log(`${(raw.length / 1048576).toFixed(1)} MB, ${rowCount} rows, ${headers.length} cols`);

    if (probe) { probed.push({ source, logicalKey: r.cfg.logicalKey, datasetId: r.resolvedId, title: r.title, modified: r.modified, rowCount, headers }); continue; }

    const check = validateHeaders({ ...r.cfg, resolvedId: r.resolvedId }, headers);
    if (!check.ok) { throw driftError({ ...r.cfg, resolvedId: r.resolvedId }, check); }

    const gz = zlib.gzipSync(raw, { level: 9 });
    fs.writeFileSync(path.join(dir, `${r.cfg.logicalKey}.csv.gz`), gz);
    totalGz += gz.length;
    files[r.cfg.logicalKey] = {
      source, logicalKey: r.cfg.logicalKey, datasetId: r.resolvedId, title: r.title, modified: r.modified,
      sourceUrl: r.url, rawBytes: raw.length, gzipBytes: gz.length, sha256Raw: sha256(raw),
      rowCount, headers, archivedAt: new Date().toISOString()
    };
  }

  if (probe) { console.log(JSON.stringify(probed, null, 2)); return { source, key, status: 'probe' }; }

  // Row-count movement is reported, never enforced. We have no evidence-based
  // anomaly threshold yet: the hospice universe legitimately moved 6852 -> 6669
  // in one quarter.
  const prior = priorRelease(source, key);
  const deltas = [];
  for (const [k, f] of Object.entries(files)) {
    const p = prior && prior.files && prior.files[k];
    if (!p || typeof p.rowCount !== 'number') { deltas.push(`${k}: ${f.rowCount} rows (no prior release)`); continue; }
    const d = f.rowCount - p.rowCount;
    const pct = p.rowCount ? (100 * d / p.rowCount) : 0;
    deltas.push(`${k}: ${p.rowCount} -> ${f.rowCount} (${d >= 0 ? '+' : ''}${d}, ${pct >= 0 ? '+' : ''}${pct.toFixed(1)}%)`);
  }

  const expectedCount = datasetsFor(reg, source).length;
  const status = skipped.length ? 'incomplete' : 'complete';
  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({
    releaseKey: key,
    source,
    schemaVersion: 2,
    capturedAt: new Date().toISOString(),
    catalog: CATALOG,
    datasetCount: Object.keys(files).length,
    expectedDatasetCount: expectedCount,
    status,
    skipped: skipped.map((s) => ({ logicalKey: s.cfg.logicalKey, reason: String(s.skipped) })),
    rowCountDeltas: deltas,
    note: 'CMS overwrites these files in place. This snapshot is the only record of this release.',
    files
  }, null, 2));

  console.log(`  archived ${Object.keys(files).length}/${expectedCount} dataset(s) -> ${path.relative(ROOT, dir)} (${(totalGz / 1048576).toFixed(1)} MB gz) [${status}]`);
  for (const d of deltas) console.log(`    rows ${d}`);
  if (skipped.length) for (const s of skipped) console.log(`    SKIPPED ${s.cfg.logicalKey}: ${String(s.skipped).split('\n')[0]}`);
  // An incomplete release is written (whatever was captured is still worth
  // keeping) but must never report success. Otherwise CMS quietly dropping a
  // dataset looks like a green run while that dataset's history stops.
  if (status === 'incomplete') {
    throw new Error(`${source}: release ${key} archived only ${Object.keys(files).length}/${expectedCount} dataset(s).\n  `
      + skipped.map((s) => `${s.cfg.logicalKey}: ${String(s.skipped).split('\n')[0]}`).join('\n  ')
      + `\n  The partial archive was kept at ${path.relative(ROOT, dir)}, but this run is NOT a success.`);
  }
  return { source, key, status, datasets: Object.keys(files).length, expected: expectedCount, deltas, skipped: skipped.length };
}

function priorRelease(source, currentKey) {
  const candidates = [];
  const push = (dir) => {
    if (!fs.existsSync(dir)) return;
    for (const d of fs.readdirSync(dir)) {
      if (Object.values(SOURCE_DIRS).includes(d)) continue;
      const mf = path.join(dir, d, 'manifest.json');
      if (d < currentKey && fs.existsSync(mf)) candidates.push({ key: d, mf });
    }
  };
  push(path.join(ARCHIVE, SOURCE_DIRS[source]));
  if (source === LEGACY_SOURCE) push(ARCHIVE);
  if (!candidates.length) return null;
  candidates.sort((a, b) => a.key.localeCompare(b.key));
  try { return JSON.parse(fs.readFileSync(candidates[candidates.length - 1].mf, 'utf8')); }
  catch { return null; }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--list')) return list();
  const reg = loadRegistry();
  const known = [...new Set(reg.datasets.map((d) => d.source))];

  let sources;
  const i = args.indexOf('--source');
  if (i >= 0) {
    sources = [args[i + 1]];
    if (!known.includes(sources[0])) { console.error(`unknown --source "${sources[0]}". Known: ${known.join(', ')}`); process.exit(2); }
  } else if (args.includes('--all')) {
    sources = known;
  } else {
    console.error(`--source <${known.join('|')}> or --all is required.`);
    process.exit(2);
  }

  const results = [];
  const failures = [];
  for (const s of sources) {
    try { results.push(await archiveSource(reg, s, args)); }
    catch (e) {
      // Per-source isolation: one family failing must never be reported as the
      // other succeeding.
      failures.push({ source: s, message: e.message });
      console.error(`\n${s}: FAILED\n${e.message}`);
    }
  }

  if (!args.includes('--print-key')) {
    console.log('\n=== summary ===');
    for (const r of results) console.log(`  ${r.source.padEnd(14)} ${String(r.key).padEnd(12)} ${r.status}${r.datasets != null ? `  ${r.datasets}/${r.expected ?? r.datasets} datasets` : ''}`);
    for (const f of failures) console.log(`  ${f.source.padEnd(14)} ${'-'.padEnd(12)} FAILED`);
  }
  if (failures.length) process.exit(1);
}

module.exports = {
  readHeader, countDataRows, validateHeaders, driftError, resolveFromItems,
  loadRegistry, datasetsFor, releaseDir, legacyDir, existingDir, releaseKeyOf,
  REGISTRY_PATH, ARCHIVE, SOURCE_DIRS
};

if (require.main === module) {
  main().catch((e) => { console.error('archive failed:', e.message); process.exit(1); });
}
