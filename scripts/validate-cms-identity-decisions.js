#!/usr/bin/env node
/**
 * Validate data/cms-hospice-identity-decisions.csv — the tracked, auditable
 * record of human identity decisions.
 *
 * This file, not the generated report under reports/, is what authorizes any
 * future ProviderExternalIdentity insert. reports/ is gitignored workspace;
 * this is version-controlled evidence of who decided what.
 *
 * Writes nothing, connects to nothing, exits non-zero on any error so a future
 * importer can refuse to run unless this passes.
 *
 * Columns:
 *   providerId          internal Provider uuid (authoritative key — provider
 *                       NAMES collide; three Providers are "Choice Hospice")
 *   providerName        human convenience only, never used as a key
 *   source              must be "cms_hospice" for now
 *   externalId          CMS CCN, exactly 6 chars, leading zeros significant
 *   identifierType      must be "ccn" for now
 *   decision            approve | reject | needs_research
 *   confidenceAtReview  matcher score at the time of review, 0-1
 *   reviewedBy          who decided
 *   reviewedAt          when, ISO-8601 date
 *   reviewNotes         why
 *
 *   node scripts/validate-cms-identity-decisions.js [path] [--allow-multi <providerId>]
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const EXPECTED_SOURCE = 'cms_hospice';
const EXPECTED_IDENTIFIER_TYPE = 'ccn';
const DECISIONS = ['approve', 'reject', 'needs_research'];
const COLS = ['providerId','providerName','source','externalId','identifierType',
              'decision','confidenceAtReview','reviewedBy','reviewedAt','reviewNotes'];

const argv = process.argv.slice(2);
const allowMulti = new Set();
let allowIncomplete = false;
const positional = [];
for (let i = 0; i < argv.length; i++) {
  if (argv[i] === '--allow-multi') { allowMulti.add(argv[++i]); continue; }
  if (argv[i] === '--allow-incomplete') { allowIncomplete = true; continue; }
  positional.push(argv[i]);
}
const file = positional[0] || path.join(ROOT, 'data', 'cms-hospice-identity-decisions.csv');

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
  return { head, rows: out.filter((r) => r.some((v) => v !== '')).map((r) => Object.fromEntries(head.map((h, i) => [h, (r[i] ?? '').trim()]))) };
}

const errors = []; const warnings = [];
const err = (m) => errors.push(m);
const warn = (m) => warnings.push(m);

if (!fs.existsSync(file)) { console.error(`Decision file not found: ${file}`); process.exit(1); }
const { head, rows } = parseCsv(fs.readFileSync(file, 'utf8'));

const missing = COLS.filter((c) => !head.includes(c));
if (missing.length) { console.error(`ERROR  missing column(s): ${missing.join(', ')}`); process.exit(1); }

const providers = new Map(
  JSON.parse(fs.readFileSync(path.join(ROOT, 'reports', 'cms-raw', 'bh-providers.json'), 'utf8'))
    .providers.map((p) => [p.id, p]));
const hospices = JSON.parse(fs.readFileSync(path.join(ROOT, 'reports', 'cms-normalized.json'), 'utf8')).hospices;

rows.forEach((r, i) => {
  const at = `row ${i + 2} (${r.providerName || r.providerId || '?'} / ${r.externalId || 'no ccn'})`;

  // 6. decision vocabulary — blank is not a decision; this file records decisions only
  if (!DECISIONS.includes(r.decision)) {
    err(`${at}: decision "${r.decision}" must be one of ${DECISIONS.join(', ')}`);
  }
  // 1. provider must exist
  if (!r.providerId) err(`${at}: providerId is required`);
  else if (!providers.has(r.providerId)) err(`${at}: providerId ${r.providerId} is not a known Provider`);
  else if (String(providers.get(r.providerId).careType || '').toLowerCase() !== 'hospice') {
    err(`${at}: Provider is careType="${providers.get(r.providerId).careType}", not hospice — the CMS hospice catalogue does not apply`);
  }
  // 4/5. fixed vocabulary for now
  if (r.source !== EXPECTED_SOURCE) err(`${at}: source "${r.source}" must be "${EXPECTED_SOURCE}"`);
  if (r.identifierType !== EXPECTED_IDENTIFIER_TYPE) err(`${at}: identifierType "${r.identifierType}" must be "${EXPECTED_IDENTIFIER_TYPE}"`);
  // 2/3/10/11. identifier rules
  if (r.externalId) {
    if (!/^[0-9A-Z]{6}$/.test(r.externalId)) err(`${at}: externalId "${r.externalId}" is not a 6-character CCN — leading zeros may have been stripped by a spreadsheet`);
    else if (!hospices[r.externalId]) err(`${at}: externalId "${r.externalId}" does not exist in the CMS catalogue`);
  } else if (r.decision === 'approve') {
    err(`${at}: approve requires an externalId`);      // 10
  }
  // 11 is permissive by construction: needs_research/reject need no externalId.
  if (r.confidenceAtReview && !(Number(r.confidenceAtReview) >= 0 && Number(r.confidenceAtReview) <= 1)) {
    warn(`${at}: confidenceAtReview "${r.confidenceAtReview}" is not between 0 and 1`);
  }
  // Auditability: an approve creates data, so it must name a reviewer and a date.
  if (r.decision === 'approve') {
    if (!r.reviewedBy) err(`${at}: approve requires reviewedBy`);
    if (!r.reviewedAt) err(`${at}: approve requires reviewedAt`);
    else if (!/^\d{4}-\d{2}-\d{2}/.test(r.reviewedAt)) err(`${at}: reviewedAt "${r.reviewedAt}" is not an ISO-8601 date`);
  } else if (r.decision && (!r.reviewedBy || !r.reviewedAt)) {
    warn(`${at}: ${r.decision} recorded without reviewedBy/reviewedAt`);
  }
});

// 7. no duplicate providerId + externalId
const seen = new Map();
rows.forEach((r, i) => {
  const k = `${r.providerId}|${r.source}|${r.externalId}`;
  if (seen.has(k)) err(`rows ${seen.get(k) + 2} and ${i + 2}: duplicate decision for providerId ${r.providerId} + externalId ${r.externalId || '(blank)'}`);
  else seen.set(k, i);
});

const approved = rows.filter((r) => r.decision === 'approve');

// 8. one Provider per external identity — mirrors @@unique([source, externalId])
const byExternal = new Map();
approved.forEach((r) => {
  const k = `${r.source}|${r.externalId}`;
  if (!byExternal.has(k)) byExternal.set(k, new Set());
  byExternal.get(k).add(r.providerId);
});
byExternal.forEach((ids, k) => {
  if (ids.size > 1) err(`${k} approved for ${ids.size} different Providers (${[...ids].join(', ')}) — violates the unique (source, externalId) invariant`);
});

// 9. one approved identity per Provider unless overridden
const byProvider = new Map();
approved.forEach((r) => {
  if (!byProvider.has(r.providerId)) byProvider.set(r.providerId, new Set());
  byProvider.get(r.providerId).add(r.externalId);
});
byProvider.forEach((ccns, pid) => {
  if (ccns.size > 1 && !allowMulti.has(pid)) {
    const p = providers.get(pid);
    err(`Provider ${pid} (${p ? p.name : '?'}) has ${ccns.size} approved CCNs (${[...ccns].join(', ')}). A Provider record holds one address. Re-run with --allow-multi ${pid} if this is genuinely a multi-location record.`);
  }
});

// 12. only approvals are ever importable
const importable = rows.filter((r) => r.decision === 'approve');
const leaked = importable.filter((r) => r.decision !== 'approve');
if (leaked.length) err(`${leaked.length} non-approved row(s) leaked into the importable set`);

// ---- provider accounting ----------------------------------------------------
// Every hospice-typed Provider must be accounted for: either it holds an accepted
// identity, or it is explicitly parked as needs_research. A provider appearing
// only on reject rows is NOT accounted for - rejecting a candidate records what
// something is not, which leaves the provider itself unresolved.
const researched = new Set(rows.filter((r) => r.decision === 'needs_research').map((r) => r.providerId));
const approvedIds = new Set(approved.map((r) => r.providerId));

approvedIds.forEach((pid) => {
  if (researched.has(pid)) {
    const p = providers.get(pid);
    err(`Provider ${pid} (${p ? p.name : '?'}) is both approved and needs_research - a settled identity cannot also be pending`);
  }
});

// A blank externalId can never be an accepted identity, whatever the decision says.
rows.forEach((r, i) => {
  if (!r.externalId && r.decision === 'approve') err(`row ${i + 2}: blank externalId cannot be an accepted identity`);
});

const hospiceProviders = [...providers.values()].filter((p) => String(p.careType || '').toLowerCase() === 'hospice');
const unaccounted = hospiceProviders.filter((p) => !approvedIds.has(p.id) && !researched.has(p.id));
if (unaccounted.length && !allowIncomplete) {
  unaccounted.forEach((p) => {
    const only = rows.filter((r) => r.providerId === p.id);
    const how = only.length ? `only ${only.map((r) => r.decision).join('/')} row(s)` : 'no rows at all';
    err(`Provider ${p.id} (${p.name}) is not accounted for - ${how}. Every hospice Provider needs an approve or a needs_research. Pass --allow-incomplete for a partial review.`);
  });
}

const counts = rows.reduce((a, r) => { a[r.decision || '(blank)'] = (a[r.decision || '(blank)'] || 0) + 1; return a; }, {});
console.log(`file        : ${path.relative(ROOT, file)}`);
console.log(`decisions   : ${rows.length}${rows.length ? '  (' + Object.entries(counts).map(([k, v]) => `${k}=${v}`).join('  ') + ')' : '  — none recorded yet'}`);
console.log(`importable  : ${importable.length} identity row(s) across ${byProvider.size} provider(s)`);
console.log(`accounting  : ${hospiceProviders.length} hospice Provider(s) - ${approvedIds.size} approved, ${researched.size} needs_research, ${unaccounted.length} unaccounted`);
if (warnings.length) { console.log(''); warnings.forEach((w) => console.log(`WARN   ${w}`)); }
if (errors.length) {
  console.log('');
  errors.forEach((e) => console.log(`ERROR  ${e}`));
  console.log(`\nFAILED — ${errors.length} error(s). Do not import.`);
  process.exit(1);
}
console.log(`\nPASSED — ${importable.length} identity row(s) authorized for import.`);
