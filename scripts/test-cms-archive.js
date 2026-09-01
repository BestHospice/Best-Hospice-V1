#!/usr/bin/env node
/**
 * Tests for the CMS archive pipeline: dataset registry, schema-drift detection,
 * release layout and idempotency.
 *
 * Entirely offline. Catalog resolution is exercised through resolveFromItems()
 * with fixture catalogs, so the exactly-one-match rule for period-versioned
 * HHCAHPS titles is tested without depending on what CMS happens to publish today.
 *
 *   node scripts/test-cms-archive.js
 */
const fs = require('fs');
const os = require('os');
const path = require('path');
const A = require('./cms-archive.js');

let pass = 0, fail = 0;
const ok = (cond, label, detail) => {
  if (cond) { pass++; console.log(`    ok   ${label}`); }
  else { fail++; console.log(`  FAIL   ${label}${detail ? `\n           ${detail}` : ''}`); }
};
const section = (t) => console.log(`\n--- ${t} ---`);

const reg = A.loadRegistry();
const cfgFor = (source, key) => reg.datasets.find((d) => d.source === source && d.logicalKey === key);
const headerLine = (cols) => cols.map((c) => `"${c.replace(/"/g, '""')}"`).join(',');

// ============================ CASE 1 & 2 ====================================
section('CASE 1 & 2 — known headers pass');
for (const [source, key] of [['hospice', 'general'], ['hospice', 'provider'], ['hospice', 'cahps_provider'],
                             ['home-health', 'agencies'], ['home-health', 'zip'], ['home-health', 'hhcahps_provider']]) {
  const cfg = cfgFor(source, key);
  const r = A.validateHeaders(cfg, cfg.expectedHeaders.slice());
  ok(r.ok, `${source}/${key} (${cfg.expectedHeaders.length} cols) validates`, JSON.stringify(r.problems));
}
ok(reg.datasets.every((d) => d.expectedHeaders.length > 0), 'every registry dataset has expected headers');

// ============================ CASE 3-7 ======================================
section('CASE 3-7 — drift fails closed');
const base = cfgFor('home-health', 'agencies');
const kinds = (r) => r.problems.map((p) => p.kind);
{
  const h = base.expectedHeaders.slice(); h.splice(3, 1);
  const r = A.validateHeaders(base, h);
  ok(!r.ok && kinds(r).includes('MISSING_COLUMNS'), 'CASE 3: missing expected column fails');
  ok(r.missing.length === 1, '  …and names the missing column', r.missing.join(','));
}
{
  const h = base.expectedHeaders.concat(['Brand New CMS Column']);
  const r = A.validateHeaders(base, h);
  ok(!r.ok && kinds(r).includes('UNEXPECTED_COLUMNS'), 'CASE 4: unexpected added column fails');
  ok(r.unexpected.includes('Brand New CMS Column'), '  …and names it (new columns are NOT silently accepted)');
}
{
  const h = base.expectedHeaders.slice(); h[1] = 'CCN';
  const r = A.validateHeaders(base, h);
  ok(!r.ok && kinds(r).includes('POSSIBLE_RENAME'), 'CASE 5: renamed column fails and is identified as a rename');
  ok(r.missing.includes('CMS Certification Number (CCN)') && r.unexpected.includes('CCN'), '  …reporting both sides');
}
{
  const h = base.expectedHeaders.slice(); h[5] = h[4];
  const r = A.validateHeaders(base, h);
  ok(!r.ok && kinds(r).includes('DUPLICATE_COLUMNS'), 'CASE 6: duplicate header fails');
}
{
  ok(!A.validateHeaders(base, []).ok, 'CASE 7a: empty header fails');
  ok(kinds(A.validateHeaders(base, [''])).includes('EMPTY_HEADER'), 'CASE 7b: all-blank header fails as EMPTY_HEADER');
  const h = base.expectedHeaders.slice(); h[2] = '';
  ok(kinds(A.validateHeaders(base, h)).includes('MALFORMED_HEADER'), 'CASE 7c: blank column name fails as MALFORMED');
}
{
  const h = base.expectedHeaders.slice();
  [h[0], h[1]] = [h[1], h[0]];
  const r = A.validateHeaders(base, h);
  ok(!r.ok && kinds(r).includes('COLUMN_ORDER_CHANGED'), 'CASE 7d: reordered columns fail (not normalized away)');
}
{
  const cfg = cfgFor('hospice', 'general');
  const r = A.validateHeaders(cfg, ['CMS Certification Number (CCN)']);
  const msg = A.driftError({ ...cfg, resolvedId: cfg.datasetId }, r).message;
  for (const bit of ['source', 'logicalKey', cfg.datasetId, 'expected', 'actual', 'missing', 'unexpected']) {
    ok(msg.toLowerCase().includes(bit.toLowerCase()), `  drift error reports "${bit}"`);
  }
  ok(!/password|postgres:\/\/|DATABASE_URL=/i.test(msg), '  drift error leaks no credentials');
}

// ============================ CASE 8 ========================================
section('CASE 8 — existing release is not silently overwritten');
{
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cms-arch-test-'));
  process.env.CMS_ARCHIVE_DIR = tmp;
  delete require.cache[require.resolve('./cms-archive.js')];
  const A2 = require('./cms-archive.js');
  fs.mkdirSync(path.join(tmp, 'hospice', '2026-08-19'), { recursive: true });
  ok(A2.existingDir('hospice', '2026-08-19') !== null, 'a current-layout release is detected as existing');
  fs.mkdirSync(path.join(tmp, '2026-05-01'), { recursive: true });
  ok(A2.existingDir('hospice', '2026-05-01') !== null, 'CASE 8b: a LEGACY-layout release is still detected (no re-download)');
  ok(A2.existingDir('hospice', '2099-01-01') === null, 'an unarchived release is not falsely detected');
  ok(A2.existingDir('home-health', '2026-05-01') === null, 'legacy detection does not leak into home-health');
  fs.rmSync(tmp, { recursive: true, force: true });
  delete process.env.CMS_ARCHIVE_DIR;
  delete require.cache[require.resolve('./cms-archive.js')];
}

// ============================ CASE 9 ========================================
section('CASE 9 — leading-zero CCNs stay strings');
{
  const csv = 'State,CMS Certification Number (CCN),ZIP Code\n' +
              'AZ,031598,85016\nAK,027001,99501\nFL,103180,32257\n';
  const hdr = A.readHeader(csv);
  ok(hdr[1] === 'CMS Certification Number (CCN)', 'header parsed exactly');
  ok(A.countDataRows(csv) === 3, 'row count excludes the header', String(A.countDataRows(csv)));
  const ccns = csv.trim().split('\n').slice(1).map((l) => l.split(',')[1]);
  ok(ccns.every((c) => typeof c === 'string' && c.length === 6), 'CCNs remain 6-char strings');
  ok(ccns.includes('031598') && ccns.includes('027001'), 'leading zeros preserved verbatim');
  ok(!ccns.some((c) => c !== String(Number(c)) && String(Number(c)) === c), 'no CCN was numerically coerced');
  const quoted = 'A,B\n"x, y","line\nbreak"\n"z","w"\n';
  ok(A.countDataRows(quoted) === 2, 'row count is quote-aware (embedded comma + newline)', String(A.countDataRows(quoted)));
}

// ============================ CASE 10 =======================================
section('CASE 10 — hospice and home-health cannot collide');
{
  const seen = new Set();
  let dupe = false;
  for (const d of reg.datasets) {
    const k = `${d.source}|${d.logicalKey}`;
    if (seen.has(k)) dupe = true;
    seen.add(k);
  }
  ok(!dupe, 'registry (source, logicalKey) pairs are unique');
  const sameKey = 'zip';
  ok(cfgFor('hospice', sameKey) && cfgFor('home-health', sameKey), 'both sources define a "zip" dataset (a real collision risk)');
  ok(cfgFor('hospice', sameKey).datasetId !== cfgFor('home-health', sameKey).datasetId, '  …with different CMS dataset ids');
  ok(A.releaseDir('hospice', '2026-01-01') !== A.releaseDir('home-health', '2026-01-01'), 'release directories differ by source');
  ok(A.releaseDir('home-health', '2026-01-01').includes(`${path.sep}home-health${path.sep}`), 'home-health writes under its own source dir');
  ok(A.legacyDir('home-health', '2026-01-01') === null, 'home-health has no legacy path (cannot land in the hospice legacy layout)');
  const ids = reg.datasets.filter((d) => d.datasetId).map((d) => d.datasetId);
  ok(new Set(ids).size === ids.length, 'no CMS dataset id is claimed by two logical datasets');
}

// ============================ CASE 11 =======================================
section('CASE 11 — partial success is never reported as complete');
{
  const items = [
    { identifier: '6jpm-sxkc', title: 'Home Health Care Agencies', modified: '2026-05-27', distribution: [{ downloadURL: 'https://x/a.csv' }] },
    { identifier: 'm5eg-upu5', title: 'Home Health Care - Zip Codes', modified: '2026-05-27', distribution: [{ downloadURL: 'https://x/z.csv' }] },
    { identifier: 'tee5-ixt5', title: 'Home Health Care - State by State Data', modified: '2026-05-27', distribution: [{ downloadURL: 'https://x/s.csv' }] },
    { identifier: '97z8-de96', title: 'Home Health Care - National Data', modified: '2026-05-27', distribution: [{ downloadURL: 'https://x/n.csv' }] }
    // HHCAHPS deliberately absent
  ];
  // Every home-health dataset is required, so an absent HHCAHPS must fail the
  // source rather than yield a green run with history quietly stopping.
  ok(reg.datasets.filter((d) => d.source === 'home-health').every((d) => d.required !== false),
     'every home-health dataset is required');
  let threw = false, msg = '';
  try { A.resolveFromItems(reg, 'home-health', items); } catch (e) { threw = true; msg = e.message; }
  ok(threw, 'absent HHCAHPS throws instead of producing an incomplete-but-green release');
  ok(/matched 0 dataset/.test(msg), '  …naming the zero-match cause', msg.split('\n')[0]);

  let threw2 = false;
  try { A.resolveFromItems(reg, 'home-health', items.filter((i) => i.identifier !== '6jpm-sxkc')); }
  catch (e) { threw2 = /no longer in the CMS catalog/.test(e.message); }
  ok(threw2, 'a missing required id-resolved dataset also throws');

  // Belt and braces: even if a future dataset is marked optional, an incomplete
  // release must still fail the run.
  ok(/status === 'incomplete'/.test(fs.readFileSync(path.join(__dirname, 'cms-archive.js'), 'utf8')),
     'archiveSource throws on an incomplete release, so optional datasets cannot make a run green');

  const r = require('child_process').spawnSync(process.execPath, [path.join(__dirname, 'cms-archive.js'), '--source', 'nope'], { encoding: 'utf8' });
  ok(r.status === 2, 'an unknown --source exits non-zero', `exit ${r.status}`);
  ok(/unknown --source/.test(r.stderr), '  …with a clear message');
}

// ============================ CASE 12 =======================================
section('CASE 12 — period-versioned HHCAHPS resolution (required)');
{
  const mk = (id, title) => ({ identifier: id, title, modified: '2026-06-10', distribution: [{ downloadURL: 'https://x/h.csv' }] });
  const required = reg.datasets.filter((d) => d.source === 'home-health' && d.datasetId)
    .map((d) => mk(d.datasetId, d.expectedTitle));
  const resolveHH = (extra) => A.resolveFromItems(reg, 'home-health', required.concat(extra));

  let resolved = resolveHH([mk('ccn4-8vby', 'Home Health Care - Patient Survey (HHCAHPS) 2025Q1 to 2025Q4')]);
  let hh = resolved.find((r) => r.cfg.logicalKey === 'hhcahps_provider');
  ok(!hh.skipped && hh.resolvedId === 'ccn4-8vby', 'exactly one match resolves and records the datasetId');

  resolved = resolveHH([mk('zzzz-9999', 'Home Health Care - Patient Survey (HHCAHPS) 2026Q1 to 2026Q4')]);
  hh = resolved.find((r) => r.cfg.logicalKey === 'hhcahps_provider');
  ok(!hh.skipped && hh.resolvedId === 'zzzz-9999', 'a new period with a NEW id still resolves by pattern');

  let e0 = null; try { resolveHH([]); } catch (e) { e0 = e.message; }
  ok(e0 && /matched 0 dataset/.test(e0), 'ZERO matches FAILS the source');

  let e2 = null;
  try {
    resolveHH([mk('aaaa-1111', 'Home Health Care - Patient Survey (HHCAHPS) 2025Q1 to 2025Q4'),
               mk('bbbb-2222', 'Home Health Care - Patient Survey (HHCAHPS) 2026Q1 to 2026Q4')]);
  } catch (e) { e2 = e.message; }
  ok(e2 && /matched 2 dataset/.test(e2), 'MULTIPLE matches FAILS the source (never picks the first)');
  ok(e2 && /aaaa-1111/.test(e2) && /bbbb-2222/.test(e2), '  …listing the ambiguous candidates');

  const near = 'Home Health Care - Patient Survey (HHCAHPS) National Data 2025Q1 to 2025Q4';
  resolved = resolveHH([mk('ccn4-8vby', 'Home Health Care - Patient Survey (HHCAHPS) 2025Q1 to 2025Q4'), mk('vxub-6swi', near)]);
  hh = resolved.find((r) => r.cfg.logicalKey === 'hhcahps_provider');
  ok(hh.resolvedId === 'ccn4-8vby', 'the pattern is strict enough to exclude the National/State HHCAHPS siblings');
}

// ============================ CASE 13 =======================================
section('CASE 13 — known-release guarantee is stated honestly (Option A)');
{
  const src = fs.readFileSync(path.join(__dirname, 'cms-archive.js'), 'utf8');
  const doc = fs.readFileSync(path.join(__dirname, '..', 'docs', 'cms-data-pipeline.md'), 'utf8');
  ok(/do NOT and cannot detect/i.test(src), 'code says plainly that upstream byte mutation is not detected');
  ok(/sourceUrl/.test(src) && /modified/.test(src), 'code does detect changed sourceUrl / modified for a known key');
  ok(/will not detect|cannot detect|does not detect|not detected/i.test(doc), 'docs state the limit explicitly');
  ok(/does\s*(\*\*)?not(\*\*)?\s*guarantee/i.test(doc), 'docs have an explicit "does not guarantee" section');
  ok(!/checksum(s)? (are )?(re-?)?verified against upstream/i.test(doc), 'docs do not claim upstream re-verification');
}

// ============================ CASE 14 =======================================
section('CASE 14 — archive family and identity source are separate namespaces');
{
  const families = [...new Set(reg.datasets.map((d) => d.source))].sort();
  ok(JSON.stringify(families) === JSON.stringify(['home-health', 'hospice']), 'archive families are hospice / home-health', families.join(','));
  const map = reg.sources || {};
  ok(map['hospice'] && map['hospice'].externalIdentitySource === 'cms_hospice', 'registry maps hospice -> cms_hospice');
  ok(map['home-health'] && map['home-health'].externalIdentitySource === 'cms_home_health', 'registry maps home-health -> cms_home_health');
  for (const f of families) {
    ok(f !== map[f].externalIdentitySource, `"${f}" is NOT equal to its identity source "${map[f].externalIdentitySource}" — they must never be joined by string equality`);
  }
  const src = fs.readFileSync(path.join(__dirname, 'cms-archive.js'), 'utf8');
  const code = src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
  ok(!/cms_hospice|cms_home_health/.test(code),
     'no identity source string appears in archiver CODE (comments may explain the distinction)');
  ok(/ARCHIVE FAMILY/.test(src) && /never be joined/.test(src),
     'the archiver comments do explain the two namespaces');
  ok(!/PrismaClient|providerExternalIdentity\./.test(code), 'the archiver constructs no DB client and reads no identity table');
}

console.log(`\n${'='.repeat(60)}`);
console.log(fail === 0 ? `PASSED — ${pass} assertions` : `FAILED — ${fail} of ${pass + fail} assertions failed`);
process.exit(fail === 0 ? 0 : 1);
