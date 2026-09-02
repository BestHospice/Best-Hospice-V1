#!/usr/bin/env node
/**
 * Guards Quality Intelligence V1 ingestion: the measure registry, the cell
 * parsers, the shared target guard, and the ingester's fail-closed behaviour.
 *
 * No database is required. The fail-closed cases run the real ingester as a
 * subprocess against the real archive with --no-db, so they prove the actual
 * exit path rather than a reimplementation of it.
 *
 * Every CCN used as a literal here is either synthetic or a public CMS
 * identifier. No production connection string, credential or host is present.
 *
 *   node scripts/test-cms-quality-ingestion.js
 */
const fs = require('fs');
const path = require('path');
const os = require('os');
const { execFileSync } = require('child_process');

const ROOT = path.join(__dirname, '..');
const P = require(path.join(ROOT, 'cms-quality-parse.js'));
const guard = require(path.join(ROOT, 'cms-ingest-guard.js'));
const MREG = require(path.join(ROOT, 'data', 'cms-hospice-quality-measures.json'));

const ING_SRC = fs.readFileSync(path.join(ROOT, 'scripts', 'import-cms-hospice-quality.js'), 'utf8');
const ING_CODE = ING_SRC.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');
const OLD_SRC = fs.readFileSync(path.join(ROOT, 'scripts', 'import-cms-hospice-data.js'), 'utf8');
const GUARD_SRC = fs.readFileSync(path.join(ROOT, 'cms-ingest-guard.js'), 'utf8');
const PARSE_SRC = fs.readFileSync(path.join(ROOT, 'cms-quality-parse.js'), 'utf8');
const PARSE_CODE = PARSE_SRC.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^\s*\/\/.*$/gm, '');

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);
const threw = (fn) => { try { fn(); return null; } catch (e) { return e; } };

// ======================= MEASURE REGISTRY ==================================
section('measure definition registry — the single source of directionality');
{
  ok(MREG.source === 'cms_hospice', '1. registry targets the cms_hospice source');
  ok(Number(MREG.minimumComparablePeers) >= 5,
     '2. registry requires at least 5 comparable peers', String(MREG.minimumComparablePeers));
  ok(Array.isArray(MREG.measures) && MREG.measures.length >= 10,
     '3. all V1 measures are declared', String(MREG.measures.length));

  const AUTHORIZED = ['H_012_00_OBSERVED', 'H_011_01_OBSERVED', 'H_008_01_OBSERVED', 'H_012_02_OBSERVED',
    'H_012_03_OBSERVED', 'H_012_04_OBSERVED', 'H_012_09_OBSERVED', 'H_012_10_OBSERVED',
    'SUMMARY_STAR_RATING', 'RECOMMEND_TBV'];
  const codes = MREG.measures.map((m) => m.measureCode);
  for (const c of AUTHORIZED) ok(codes.includes(c), `4. authorized measure ${c} is declared`);
  ok(codes.length === AUTHORIZED.length,
     '5. NO measure beyond the authorized V1 set is declared', codes.join(', '));

  // The whole safety property of the registry.
  const EXPECTED_DIRECTION = {
    H_012_00_OBSERVED: 'higher_better',   // HCI overall: one point per indicator met, 0-10
    H_011_01_OBSERVED: 'higher_better',   // HVLDL
    H_008_01_OBSERVED: 'higher_better',   // HIS composite
    H_012_02_OBSERVED: 'lower_better',    // gaps in nursing visits
    H_012_03_OBSERVED: 'lower_better',    // early live discharges
    H_012_04_OBSERVED: 'lower_better',    // late live discharges
    H_012_09_OBSERVED: 'higher_better',   // SN minutes on weekends
    H_012_10_OBSERVED: 'higher_better',   // visits near death
    SUMMARY_STAR_RATING: 'higher_better',
    RECOMMEND_TBV: 'higher_better'
  };
  for (const m of MREG.measures) {
    ok(m.direction === EXPECTED_DIRECTION[m.measureCode],
       `6. ${m.measureCode} direction is ${EXPECTED_DIRECTION[m.measureCode]}`, m.direction);
    ok(!!m.directionSource, `   …and cites a CMS source for that direction`);
    ok(!!m.cmsMeasureName, `   …and records CMS's own measure name for drift detection`);
  }
  const lower = MREG.measures.filter((m) => m.direction === 'lower_better').length;
  ok(lower === 3, '7. exactly three lower-is-better measures are declared', String(lower));

  // CMS's raw percentile is a monotone rank of the RAW value with no directional
  // correction, so it can never be a quality rank.
  ok(!codes.some((c) => /_PERCENTILE$/.test(c)),
     '8. no CMS _PERCENTILE field is declared as a surfaced measure');
  // Scoped to the specific construct: the ingester DOES mention _PERCENTILE,
  // but only to refuse it. An unscoped "does not contain" assertion would have
  // been satisfied by the guard's own error message.
  ok(/_PERCENTILE\$\/\.test\(String\(m\.measureCode\)\)/.test(ING_CODE),
     '   …and the ingester actively REFUSES any _PERCENTILE measure code');
  ok(!/'[A-Z_0-9]*_PERCENTILE'/.test(ING_CODE),
     '   …and never names a _PERCENTILE code as data to store');

  const dims = new Set((MREG.dimensions || []).map((d) => d.key));
  ok(MREG.measures.every((m) => dims.has(m.dimension)),
     '9. every measure belongs to a declared dimension');
  ok((MREG.dimensions || []).filter((d) => d.conditional === true).length === 1,
     '10. exactly one dimension is conditional (family caregiver experience)');
  const cahps = MREG.measures.filter((m) => m.family === 'cahps');
  ok(cahps.length === 2 && cahps.every((m) => m.dimension === 'familyExperience'),
     '11. both CAHPS measures sit in the conditional dimension');
  ok(MREG.measures.find((m) => m.measureCode === 'SUMMARY_STAR_RATING').valueColumn === 'Star Rating',
     '12. the star rating reads the Star Rating column, not Score');
}

// ======================= CELL PARSERS ======================================
section('score parsing — the five real CMS value shapes');
{
  const r1 = P.parseScoreCell('96.62');
  ok(r1.valueNumeric === 96.62 && r1.suppressed === false, '13. a plain number parses');
  ok(r1.valueRaw === '96.62', '   …and the raw cell is preserved verbatim');

  const r2 = P.parseScoreCell('Not Available');
  ok(r2.valueNumeric === null, '14. "Not Available" yields NULL, not 0');
  ok(r2.suppressed === true, '   …and is marked suppressed');
  ok(r2.valueRaw === 'Not Available', '   …and keeps CMS\'s exact word');

  const r3 = P.parseScoreCell('Not Applicable');
  ok(r3.valueNumeric === null && r3.suppressed === true, '15. "Not Applicable" yields NULL and suppressed');

  // 1,352 rows in the real archive glue the footnote into the Score cell.
  const r4 = P.parseScoreCell('Not Available(12)');
  ok(r4.valueNumeric === null, '16. "Not Available(12)" yields NULL, not 12');
  ok(r4.suppressed === true, '   …and is marked suppressed');
  ok(JSON.stringify(r4.footnoteCodes) === '["12"]', '   …and the glued footnote is recovered as a code');
  ok(r4.valueRaw === 'Not Available(12)', '   …and the raw cell is preserved verbatim');

  const r5 = P.parseScoreCell('1,152');
  ok(r5.valueNumeric === 1152, '17. a thousands-separated number parses to 1152, not 1');
  const r6 = P.parseScoreCell('17,677');
  ok(r6.valueNumeric === 17677, '   …and 17,677 parses to 17677');
  const r7 = P.parseScoreCell('159,714,660');
  ok(r7.valueNumeric === 159714660, '   …and a multi-group value parses');

  const r8 = P.parseScoreCell('-');
  ok(r8.valueNumeric === null && r8.suppressed === true, '18. the "-" sentinel is not a negative number');
  const r9 = P.parseScoreCell('');
  ok(r9.valueNumeric === null && r9.suppressed === true, '19. an empty cell yields NULL and suppressed');

  // Fail closed: Yes/No exists in the archive but only on descriptive measures.
  // A surfaced measure suddenly carrying it means CMS redefined it.
  ok(threw(() => P.parseScoreCell('Yes', 'H_012_00_OBSERVED')) instanceof P.QualityParseError,
     '20. "Yes" on a surfaced measure FAILS CLOSED rather than becoming null');
  ok(threw(() => P.parseScoreCell('No')) instanceof P.QualityParseError, '   …and so does "No"');
  ok(threw(() => P.parseScoreCell('1,2')) instanceof P.QualityParseError,
     '21. a malformed thousands group fails closed instead of parsing as 12');
  ok(threw(() => P.parseScoreCell('96.62(3)')) instanceof P.QualityParseError,
     '22. a real value with a trailing (n) fails closed — never silently truncated');
  ok(threw(() => P.parseScoreCell('Mostly fine')) instanceof P.QualityParseError,
     '23. a novel sentinel fails closed rather than being absorbed');
}

section('footnote parsing — multi-valued, never an integer');
{
  ok(JSON.stringify(P.parseFootnoteCell('-')) === '[]', '24. "-" means no footnote');
  ok(JSON.stringify(P.parseFootnoteCell('')) === '[]', '   …and so does an empty cell');
  ok(JSON.stringify(P.parseFootnoteCell('11')) === '["11"]', '25. a single footnote is an array of one');
  ok(JSON.stringify(P.parseFootnoteCell('2,5')) === '["2","5"]', '26. "2,5" becomes two codes, not the number 25');
  ok(JSON.stringify(P.parseFootnoteCell('1,5')) === '["1","5"]', '   …and "1,5" becomes two codes');
  ok(JSON.stringify(P.parseFootnoteCell('6,7')) === '["6","7"]', '   …and "6,7" becomes two codes');
  ok(threw(() => P.parseFootnoteCell('2;5')) instanceof P.QualityParseError,
     '27. an unknown footnote separator fails closed');
}

section('measurement period parsing — both CMS formats, no timezone drift');
{
  const a = P.parsePeriodCell('01/01/2023 - 12/31/2024');
  ok(a.start === '2023-01-01' && a.end === '2024-12-31',
     '28. the provider-file format (spaced dash) parses', JSON.stringify(a));
  const b = P.parsePeriodCell('10/01/2023-09/30/2025');
  ok(b.start === '2023-10-01' && b.end === '2025-09-30',
     '29. the CAHPS format (unspaced dash) parses', JSON.stringify(b));
  const c = P.parsePeriodCell('10/01/2024 - 09/30/2025');
  ok(c.start === '2024-10-01' && c.end === '2025-09-30', '30. the composite-measure period parses');

  ok(typeof a.start === 'string' && typeof a.end === 'string',
     '31. periods are STRINGS, never JS Dates — no local-time truncation is possible');
  ok(!/new Date\(/.test(PARSE_CODE.split('function parsePeriodCell')[1].split('function parseStarRatingCell')[0] || ''),
     '   …and parsePeriodCell constructs no Date for the returned value');

  ok(P.parsePeriodCell('-') === null, '32. a sentinel period yields null, not an epoch date');
  ok(threw(() => P.parsePeriodCell('02/30/2023 - 12/31/2024')) instanceof P.QualityParseError,
     '33. an impossible calendar date fails closed instead of rolling forward');
  ok(P.parsePeriodCell('02/29/2024 - 12/31/2024').start === '2024-02-29',
     '34. a real leap day is accepted');
  ok(threw(() => P.parsePeriodCell('02/29/2023 - 12/31/2024')) instanceof P.QualityParseError,
     '   …and a non-leap 29 February is refused');
  ok(threw(() => P.parsePeriodCell('12/31/2024 - 01/01/2023')) instanceof P.QualityParseError,
     '35. a period that ends before it starts fails closed');
  ok(threw(() => P.parsePeriodCell('2023-01-01 to 2024-12-31')) instanceof P.QualityParseError,
     '36. an unrecognised period format fails closed');
}

section('star rating and denominator parsing');
{
  ok(P.parseStarRatingCell('3') === 3, '37. a whole star rating parses');
  ok(P.parseStarRatingCell('Not Available') === null, '38. an unpublished star rating is null, not 0');
  ok(P.parseStarRatingCell('Not Applicable') === null, '   …and so is "Not Applicable"');
  ok(threw(() => P.parseStarRatingCell('6')) instanceof P.QualityParseError,
     '39. a star rating outside 1-5 fails closed');
  ok(threw(() => P.parseStarRatingCell('3.5')) instanceof P.QualityParseError,
     '   …and a fractional star fails closed');
  ok(P.parseDenominatorCell('40,628') === 40628, '40. a thousands-separated denominator parses');
  ok(P.parseDenominatorCell('Not Available') === null,
     '41. an unpublished denominator is null — never "zero patients"');
}

section('CSV parsing — quote awareness');
{
  // The bug this prevents: a naive split() on the CAHPS file reads Measure NAMES
  // as measure CODES, because the names contain commas and the file quotes them.
  const csv = '"CMS Certification Number (CCN)","Measure Code","Measure Name","Score"\n'
    + '"031598","RATING_TBV","Caregivers rated the hospice agency a 9 or 10, top box","78"\n';
  const r = P.parseCsv(csv);
  ok(r.head.length === 4, '42. quoted headers parse to the right column count', String(r.head.length));
  ok(r.rows[0]['Measure Code'] === 'RATING_TBV',
     '43. a measure code is not corrupted by a comma inside the adjacent quoted name');
  ok(r.rows[0]['Measure Name'] === 'Caregivers rated the hospice agency a 9 or 10, top box',
     '   …and the embedded comma survives inside the name');
  ok(r.rows[0]['Score'] === '78', '   …and the following column is not shifted');
  const lz = P.parseCsv('a,b\n031598,A01500\n');
  ok(lz.rows[0].a === '031598', '44. a leading-zero CCN stays a string');
  ok(lz.rows[0].b === 'A01500', '   …and an alphanumeric CCN is untouched');
  const esc = P.parseCsv('a,b\n"say ""hi""",2\n');
  ok(esc.rows[0].a === 'say "hi"', '45. escaped double quotes are unescaped correctly');
}

// ======================= SHARED GUARD ======================================
section('target guard — shared, and provably not diverged from the facility importer');
{
  const grab = (name) => {
    const m = OLD_SRC.match(new RegExp(`const ${name} = \\[([\\s\\S]*?)\\];`));
    return m ? [...m[1].matchAll(/'([^']+)'/g)].map((x) => x[1]) : null;
  };
  const oldShadow = grab('SHADOW_IDENTIFIERS');
  const oldProd = grab('PRODUCTION_IDENTIFIERS');
  ok(Array.isArray(oldShadow) && oldShadow.length === 4,
     '46. the facility importer\'s shadow list was located for comparison', String(oldShadow && oldShadow.length));
  ok(JSON.stringify([...guard.SHADOW_IDENTIFIERS].sort()) === JSON.stringify([...oldShadow].sort()),
     '47. the shared shadow identifier list is IDENTICAL to the facility importer\'s');
  ok(JSON.stringify([...guard.PRODUCTION_IDENTIFIERS].sort()) === JSON.stringify([...oldProd].sort()),
     '48. the shared production identifier list is IDENTICAL to the facility importer\'s');

  for (const [url, want, label] of [
    ['postgresql://u@localhost:5432/bh_quality_test', 'NON_PRODUCTION', 'a local disposable database'],
    ['postgresql://besthospice_db_user:x@dpg-d5hhmb4hg0os7380cecg-a/besthospice_db', 'PRODUCTION', 'production by name and host'],
    ['postgresql://u:x@dpg-d60g7h0gjchc73f306j0-a/besthospice_shadow_2', 'SHADOW', 'the shadow database'],
    ['postgresql://u:x@besthospice%5Fdb.example/db', 'PRODUCTION', 'a percent-encoded production identifier'],
    ['postgresql://u:x@some-host.oregon-postgres.render.com/whatever', 'HOSTED_UNKNOWN', 'an unrecognised Render host'],
    ['postgresql://u:x@dpg-abc123def456/whatever', 'HOSTED_UNKNOWN', 'an unrecognised Render internal host id'],
    ['postgresql://u@localhost/besthospice_db1', 'NON_PRODUCTION', 'besthospice_db1 is NOT besthospice_db'],
    ['postgresql://u@localhost/dpg-scratch', 'NON_PRODUCTION', 'a local db merely named like a Render host']
  ]) ok(guard.classifyTarget(url).kind === want, `49. ${label} classifies as ${want}`, guard.classifyTarget(url).kind);

  ok(guard.classifyTarget('postgresql://u:x@dpg-d60g7h0gjchc73f306j0-a/besthospice_shadow_2').kind === 'SHADOW',
     '50. the shadow is matched BEFORE production, so it can never reach an authorizable class');

  // Operation is part of the hashed bytes, so tokens cannot cross operations.
  const facts = { dbSource: 'cms_hospice', releaseKey: '2026-08-19', manifestSha256: 'a'.repeat(64) };
  const tQ = guard.authorizationToken({ ...facts, operation: 'cms-hospice-quality-ingest' });
  const tF = guard.authorizationToken({ ...facts, operation: 'cms-hospice-production-ingest' });
  ok(tQ !== tF, '51. a facility-ingestion token does NOT authorize a quality ingestion');
  ok(/^[0-9a-f]{64}$/.test(tQ), '52. the token is 64 lowercase hex characters');
  ok(guard.authorizationToken({ ...facts, operation: 'cms-hospice-quality-ingest', releaseKey: '2026-08-18' }) !== tQ,
     '53. a token for another release does not match');
  ok(guard.authorizationToken({ ...facts, operation: 'cms-hospice-quality-ingest', manifestSha256: 'b'.repeat(64) }) !== tQ,
     '54. a token for another manifest does not match');
  ok(guard.tokenMatches(tQ, tQ) === true && guard.tokenMatches(tQ.slice(0, 63), tQ) === false,
     '55. token comparison is exact and length-safe');
  ok(!/timingSafeEqual\(a, b\)[\s\S]*?if \(a\.length/.test(GUARD_SRC),
     '56. lengths are compared BEFORE timingSafeEqual, which throws on a mismatch');

  ok(guard.scrub('connect postgresql://user:pw@host/besthospice_db failed').indexOf('besthospice_db') === -1,
     '57. log scrubbing removes production identifiers');
  ok(guard.redact('postgresql://u:secret@h/db').indexOf('secret') === -1,
     '58. redaction removes a whole connection URL');
}

// ======================= INGESTER SOURCE AUDIT =============================
section('ingester — structure and safety');
{
  for (const [re, label] of [
    [/--force|allowProduction|--allow-production|--unsafe|--skip-guard|forceProd|--force-prod/i, 'no generic bypass flag'],
    [/migrate\s+dev|db\s+push|migrate\s+reset/i, 'no destructive Prisma command'],
    [/besthospice_db|dpg-|besthospice_shadow/i, 'no production or shadow identifier is hard-coded in the ingester'],
    [/DROP |TRUNCATE|DELETE FROM/i, 'no destructive SQL'],
    [/121509|ISLANDS HOSPICE|Vrablic/i, 'no real provider is special-cased']
  ]) ok(!re.test(ING_CODE), `59. ${label}`);

  ok(/opts = \{ write: false/.test(ING_CODE), '60. dry run is the DEFAULT — write is opt-in');
  ok(/if \(!opts\.write\)[\s\S]{0,200}DRY RUN/.test(ING_CODE), '   …and the dry-run branch returns before any transaction');
  ok(/if \(opts\.noDb && opts\.write\) usage/.test(ING_CODE), '61. --no-db and --write are mutually exclusive');

  // It must never create a release: that is the facility importer's job, and one
  // writer is what keeps the two datasets provably from the same archive.
  ok(!/cmsRelease\.create|INSERT INTO "CmsRelease"/.test(ING_CODE),
     '62. the quality ingester NEVER creates a CmsRelease');
  ok(/RELEASE NOT INGESTED/.test(ING_SRC), '   …and it fails closed when the release is absent');
  ok(/ARCHIVE MISMATCH/.test(ING_SRC) && /release\.manifestSha256 !== arc\.manifestSha256/.test(ING_CODE),
     '63. it refuses an archive whose manifest differs from the stored release');
  ok(/RELEASE UNVERIFIABLE/.test(ING_SRC), '   …and refuses a release with a NULL manifestSha256');

  ok(/CHRONOLOGY VIOLATION/.test(ING_SRC) && /latest\.releaseKey > arc\.releaseKey/.test(ING_CODE),
     '64. an older-than-latest release is refused (chronological safety)');
  ok(/pg_advisory_xact_lock/.test(ING_CODE), '65. ingestion is serialised with a transaction-scoped advisory lock');
  const tx = ING_CODE.match(/\$transaction\(async \(tx\) => \{([\s\S]*?)\n    \}, \{ timeout/);
  ok(!!tx, '66. the write path is one transaction');
  ok(tx && /^\s*await tx\.\$executeRawUnsafe\('SELECT pg_advisory_xact_lock/.test(tx[1].split('\n').filter((l) => l.trim())[0] + '\n'),
     '   …and the advisory lock is its FIRST statement');
  ok(tx && /cms-quality-ingest:/.test(tx[1]),
     '67. the lock name is distinct from the facility importer\'s, so the two do not block each other');
  ok(tx && /chronology violation detected inside the transaction/.test(tx[1]),
     '68. chronology is re-checked AFTER the lock is held');
  ok(tx && /CmsMeasureDefinition[\s\S]*CmsFacilityMeasure/.test(tx[1]),
     '69. definitions are written BEFORE measurements, so the FK can never be violated');
  ok(tx && /postcondition/.test(tx[1]), '70. postconditions are asserted inside the transaction');
  ok(tx && /suppressed measurement\(s\) carry a numeric value/.test(tx[1]),
     '71. a postcondition proves no suppressed row was coerced to a number');

  ok(/ON CONFLICT \("facilityId","measureCode","releaseId"\) DO UPDATE/.test(ING_CODE),
     '72. measurement writes are idempotent on the natural key');
  ok(/ON CONFLICT \("source","measureCode"\) DO UPDATE/.test(ING_CODE),
     '73. definition writes are idempotent on (source, measureCode)');

  // The timezone lesson.
  ok(/\{b\+12\}::date/.test(ING_CODE) && /\{b\+13\}::date/.test(ING_CODE),
     '74. periodStart and periodEnd are both bound to ::date parameters');
  ok(/r\.periodStart, r\.periodEnd/.test(ING_CODE),
     '   …from the parser\'s YYYY-MM-DD strings, never a JS Date');
  ok(!/new Date\([^)]*period/i.test(ING_CODE), '75. no Date object is built from a period anywhere');

  ok(/parseScoreCell|parseFootnoteCell|parsePeriodCell/.test(ING_CODE),
     '76. the ingester reuses the shared cell parsers rather than reimplementing them');
  ok(/require\(path\.join\(ROOT, 'cms-ingest-guard\.js'\)\)/.test(ING_CODE),
     '77. it reuses the shared target guard');
  ok(!/sha256Raw[\s\S]{0,80}skip|ignore checksum/i.test(ING_CODE), '78. no checksum check can be skipped');
  ok(/got !== want/.test(ING_CODE) && /checksum mismatch/.test(ING_SRC),
     '79. every used dataset\'s sha256 is matched against the manifest');
  ok(/header does not match the registry contract/.test(ING_SRC)
     && /header does not match the headers recorded in the manifest/.test(ING_SRC),
     '80. headers are checked against BOTH the manifest and the tracked registry');
  ok(/schemaVersion >= 2/.test(ING_SRC), '81. Archive V2 manifest facts are required, never inferred');
  ok(!/for\s*\([^)]*\)\s*\{[^}]*await prisma\./.test(ING_CODE),
     '82. no query is issued inside a loop over facilities in the planning phase');
}

// ======================= FAIL-CLOSED, END TO END ============================
section('fail-closed behaviour, running the real ingester against the real archive');
const ARCHIVE = path.join(ROOT, 'reports', 'cms-archive', 'hospice', '2026-08-19');
const haveArchive = fs.existsSync(path.join(ARCHIVE, 'manifest.json'));
if (!haveArchive) {
  console.log('  (skipped: reports/cms-archive/hospice/2026-08-19 is not present)');
} else {
  const run = (env, args) => {
    try {
      const out = execFileSync(process.execPath,
        [path.join(ROOT, 'scripts', 'import-cms-hospice-quality.js'), ...args],
        { cwd: ROOT, env: { ...process.env, ...env }, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] });
      return { code: 0, out };
    } catch (e) {
      return { code: e.status === undefined ? -1 : e.status, out: String(e.stdout || '') + String(e.stderr || '') };
    }
  };
  const tmpRegistry = (mutate) => {
    const copy = JSON.parse(JSON.stringify(MREG));
    mutate(copy);
    const f = path.join(os.tmpdir(), `bh-q-reg-${process.pid}-${Math.random().toString(36).slice(2)}.json`);
    fs.writeFileSync(f, JSON.stringify(copy));
    return f;
  };

  const baseline = run({}, ['--release', '2026-08-19', '--no-db']);
  ok(baseline.code === 0, '83. the unmodified registry validates against the real archive', String(baseline.code));
  ok(/ARCHIVE-ONLY VALIDATION/.test(baseline.out), '   …and --no-db contacts no database');
  ok(/higher_better/.test(baseline.out) && /lower_better/.test(baseline.out),
     '84. the plan prints each measure\'s direction from the registry');

  // 4: unknown / absent required measure code
  let f = tmpRegistry((r) => { r.measures[0].measureCode = 'H_999_99_OBSERVED'; });
  let res = run({ CMS_QUALITY_MEASURES_PATH: f }, ['--release', '2026-08-19', '--no-db']);
  ok(res.code === 1 && /MEASURE DRIFT/.test(res.out) && /is ABSENT/.test(res.out),
     '85. an unknown required measure code FAILS CLOSED', `exit ${res.code}`);
  fs.unlinkSync(f);

  // 4: CMS renamed a measure
  f = tmpRegistry((r) => { r.measures[0].cmsMeasureName = 'Some Other Thing CMS Now Calls It'; });
  res = run({ CMS_QUALITY_MEASURES_PATH: f }, ['--release', '2026-08-19', '--no-db']);
  ok(res.code === 1 && /MEASURE DRIFT/.test(res.out) && /renamed or redefined/.test(res.out),
     '86. a CMS measure rename FAILS CLOSED rather than being relabelled', `exit ${res.code}`);
  fs.unlinkSync(f);

  // absent denominator code
  f = tmpRegistry((r) => { r.measures[0].denominatorCode = 'H_999_99_DENOMINATOR'; });
  res = run({ CMS_QUALITY_MEASURES_PATH: f }, ['--release', '2026-08-19', '--no-db']);
  ok(res.code === 1 && /denominator code[\s\S]*ABSENT/.test(res.out),
     '87. an absent denominator code FAILS CLOSED', `exit ${res.code}`);
  fs.unlinkSync(f);

  // a measure with no direction can never reach the database
  f = tmpRegistry((r) => { delete r.measures[0].direction; });
  res = run({ CMS_QUALITY_MEASURES_PATH: f }, ['--release', '2026-08-19', '--no-db']);
  ok(res.code === 1 && /MEASURE REGISTRY INVALID/.test(res.out) && /direction/.test(res.out),
     '88. a measure with no direction is REFUSED', `exit ${res.code}`);
  fs.unlinkSync(f);

  f = tmpRegistry((r) => { r.measures[0].direction = 'contextual'; });
  res = run({ CMS_QUALITY_MEASURES_PATH: f }, ['--release', '2026-08-19', '--no-db']);
  ok(res.code === 1 && /only higher_better or lower_better/.test(res.out),
     '89. an unsupported direction value is REFUSED', `exit ${res.code}`);
  fs.unlinkSync(f);

  // a CMS _PERCENTILE field can never be declared surfaced
  f = tmpRegistry((r) => { r.measures[0].measureCode = 'H_012_02_PERCENTILE'; });
  res = run({ CMS_QUALITY_MEASURES_PATH: f }, ['--release', '2026-08-19', '--no-db']);
  ok(res.code === 1 && /_PERCENTILE/.test(res.out) && /never be surfaced/.test(res.out),
     '90. a CMS _PERCENTILE measure is REFUSED as a quality rank', `exit ${res.code}`);
  fs.unlinkSync(f);

  f = tmpRegistry((r) => { r.minimumComparablePeers = 2; });
  res = run({ CMS_QUALITY_MEASURES_PATH: f }, ['--release', '2026-08-19', '--no-db']);
  ok(res.code === 0, '91. lowering minimumComparablePeers in the registry does not break ingestion');
  const q = require(path.join(ROOT, 'cms-hospice-quality.js'));
  ok(q.MIN_COMPARABLE_PEERS >= 5,
     '   …and the service still enforces a hard floor of 5 regardless', String(q.MIN_COMPARABLE_PEERS));
  fs.unlinkSync(f);

  // production/shadow refusal. These exit BEFORE any client is constructed, so no
  // connection is attempted. The production host form used here is the INTERNAL
  // Render host id, which does not resolve in DNS.
  res = run({ DATABASE_URL: 'postgresql://besthospice_db_user:x@dpg-d5hhmb4hg0os7380cecg-a/besthospice_db' },
    ['--release', '2026-08-19']);
  ok(res.code === 1 && /production database/.test(res.out) && /ZERO writes/.test(res.out),
     '92. a production target with NO authorization is refused', `exit ${res.code}`);
  ok(!/PRODUCTION TARGET AUTHORIZED/.test(res.out), '   …and is never announced as authorized');

  res = run({ DATABASE_URL: 'postgresql://besthospice_db_user:x@dpg-d5hhmb4hg0os7380cecg-a/besthospice_db' },
    ['--release', '2026-08-19', '--production-authorization', 'f'.repeat(64)]);
  ok(res.code === 1 && /does not match this release/.test(res.out),
     '93. a production target with a WRONG token is refused', `exit ${res.code}`);
  ok(!new RegExp(guard.authorizationToken({
    operation: 'cms-hospice-quality-ingest', dbSource: 'cms_hospice', releaseKey: '2026-08-19',
    manifestSha256: guard.sha256Hex(fs.readFileSync(path.join(ARCHIVE, 'manifest.json')))
  })).test(res.out), '   …and the correct token is NOT echoed in the failure');

  res = run({ DATABASE_URL: 'postgresql://u:x@dpg-d60g7h0gjchc73f306j0-a/besthospice_shadow_2' },
    ['--release', '2026-08-19']);
  ok(res.code === 1 && /shadow database/.test(res.out) && /no\s*\n?\s*.{0,20}authorization that permits it/.test(res.out),
     '94. the shadow database is refused with NO authorization path', `exit ${res.code}`);

  res = run({ DATABASE_URL: 'postgresql://u:x@x.oregon-postgres.render.com/whatever' }, ['--release', '2026-08-19']);
  ok(res.code === 1 && /unrecognised hosted\/managed database/.test(res.out),
     '95. an unrecognised hosted database is refused', `exit ${res.code}`);

  for (const [args, label] of [
    [['--force'], 'a --force flag does not exist'],
    [['--allow-production'], 'an --allow-production flag does not exist'],
    [['--skip-guard'], 'a --skip-guard flag does not exist'],
    [['--production-authorization', 'nothex'], 'a malformed token is rejected at the CLI'],
    [['--no-db', '--write'], '--no-db with --write is rejected']
  ]) {
    const r = run({}, args);
    ok(r.code === 2 || (r.code === 1 && /Usage error/.test(r.out)), `96. ${label}`, `exit ${r.code}`);
  }

  const tok = run({}, ['--release', '2026-08-19', '--print-production-authorization']);
  ok(tok.code === 0 && /cms-hospice-quality-ingest/.test(tok.out),
     '97. --print-production-authorization reports the quality operation');
  ok(/token\s+:\s+[0-9a-f]{64}/.test(tok.out), '   …and prints a 64-hex token');
  ok(!/postgres|password/i.test(tok.out), '   …and prints no credential');
}

console.log(`\n${'='.repeat(60)}`);
console.log(fail === 0 ? `PASSED — ${pass} assertions` : `FAILED — ${fail} of ${pass + fail} assertions failed`);
process.exit(fail === 0 ? 0 : 1);
