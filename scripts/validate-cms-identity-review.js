#!/usr/bin/env node
/**
 * Validate a completed CMS identity review file before any database import.
 *
 * This is the gate between a human's spreadsheet and ProviderExternalIdentity.
 * It writes nothing and connects to nothing. Exits non-zero on any error, so a
 * future importer can refuse to run unless this passes.
 *
 * The rules mirror the database invariants deliberately: @@unique([source,
 * externalId]) means one CMS certification maps to one Provider, and a review
 * file that violates that would fail at INSERT time with half the rows already
 * written. Catch it here instead.
 *
 *   node scripts/validate-cms-identity-review.js [path/to/review.csv]
 *   node scripts/validate-cms-identity-review.js --allow-multi <providerId>
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const ALLOWED = ['approve', 'reject', 'needs_research', ''];
const REQUIRED_COLS = ['providerId', 'proposedCcn', 'cmsName', 'proposedStatus', 'reviewDecision', 'reviewNotes'];

const args = process.argv.slice(2);
const allowMulti = new Set();
const positional = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === '--allow-multi') { allowMulti.add(args[++i]); continue; }
  positional.push(args[i]);
}
const file = positional[0] || path.join(ROOT, 'reports', 'cms-hospice-identity-review.csv');

// ---- minimal RFC4180 reader; must not coerce anything to a number ----------
function parseCsv(text) {
  const rows = []; let row = []; let cur = ''; let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { cur += '"'; i++; } else q = false; }
      else cur += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(cur); cur = ''; }
    else if (c === '\n') { row.push(cur); rows.push(row); row = []; cur = ''; }
    else if (c !== '\r') cur += c;
  }
  if (cur !== '' || row.length) { row.push(cur); rows.push(row); }
  const head = rows.shift();
  return rows.filter((r) => r.some((v) => v !== '')).map((r) => Object.fromEntries(head.map((h, i) => [h, r[i] ?? ''])));
}

const errors = [];
const warnings = [];
const err = (m) => errors.push(m);
const warn = (m) => warnings.push(m);

if (!fs.existsSync(file)) { console.error(`Review file not found: ${file}`); process.exit(1); }
const rows = parseCsv(fs.readFileSync(file, 'utf8'));

for (const c of REQUIRED_COLS) if (!(c in (rows[0] || {}))) err(`missing required column: ${c}`);
if (errors.length) { errors.forEach((e) => console.error(`ERROR  ${e}`)); process.exit(1); }

// Reference data: providers and the CMS catalogue are the authority on whether
// an id or a CCN is real.
const providers = new Map(
  JSON.parse(fs.readFileSync(path.join(ROOT, 'reports', 'cms-raw', 'bh-providers.json'), 'utf8'))
    .providers.map((p) => [p.id, p]));
const hospices = JSON.parse(fs.readFileSync(path.join(ROOT, 'reports', 'cms-normalized.json'), 'utf8')).hospices;

rows.forEach((r, i) => {
  const at = `row ${i + 2} (${r.providerName || '?'} / ${r.proposedCcn || 'no ccn'})`;
  const d = (r.reviewDecision || '').trim();

  // 1. decision vocabulary
  if (!ALLOWED.includes(d)) err(`${at}: reviewDecision "${r.reviewDecision}" is not one of ${ALLOWED.filter(Boolean).join(', ')} or blank`);
  if (d !== r.reviewDecision) warn(`${at}: reviewDecision has surrounding whitespace`);

  // 2. CCN must survive as an exact string
  if (r.proposedCcn) {
    if (!/^[0-9A-Z]{6}$/.test(r.proposedCcn)) err(`${at}: proposedCcn "${r.proposedCcn}" is not a 6-character CCN - leading zeros may have been stripped by a spreadsheet`);
    else if (!hospices[r.proposedCcn]) err(`${at}: proposedCcn "${r.proposedCcn}" does not exist in the CMS catalogue`);
  }

  // 3. approved rows need the fields an identity row is built from
  if (d === 'approve') {
    if (!r.providerId) err(`${at}: approved row has no providerId`);
    if (!r.proposedCcn) err(`${at}: approved row has no proposedCcn`);
    if (!r.cmsName) err(`${at}: approved row has no cmsName`);
    if (r.proposedStatus === 'no_match') err(`${at}: approved a no_match row - there is no external identifier to accept`);
    if (r.contestedCcn === 'yes' && !r.reviewNotes.trim()) err(`${at}: approved a CONTESTED CCN without reviewNotes explaining why this Provider owns it`);
  }

  // 4. referential sanity
  if (r.providerId && !providers.has(r.providerId)) err(`${at}: providerId ${r.providerId} is not a known Provider`);
  else if (d === 'approve' && String(providers.get(r.providerId).careType || '').toLowerCase() !== 'hospice') {
    err(`${at}: approved a non-hospice Provider against the CMS hospice catalogue`);
  }
});

const approved = rows.filter((r) => (r.reviewDecision || '').trim() === 'approve');

// 5. one accepted identity per CMS certification - mirrors @@unique([source, externalId])
const byCcn = new Map();
approved.forEach((r) => { if (!byCcn.has(r.proposedCcn)) byCcn.set(r.proposedCcn, new Set()); byCcn.get(r.proposedCcn).add(r.providerId); });
byCcn.forEach((ids, ccn) => {
  if (ids.size > 1) err(`CCN ${ccn} approved for ${ids.size} different Providers (${[...ids].join(', ')}) - violates the unique (source, externalId) invariant`);
});
approved.forEach((r, i) => {
  const dupe = approved.findIndex((o, j) => j !== i && o.providerId === r.providerId && o.proposedCcn === r.proposedCcn);
  if (dupe > i) err(`duplicate approved row for provider ${r.providerId} + CCN ${r.proposedCcn}`);
});

// 6. one accepted identity per Provider unless explicitly allowed. A Provider
// holds a single address, so several CCNs usually means two locations were
// merged into one record - which is a data problem, not a match to accept.
const byProvider = new Map();
approved.forEach((r) => { if (!byProvider.has(r.providerId)) byProvider.set(r.providerId, new Set()); byProvider.get(r.providerId).add(r.proposedCcn); });
byProvider.forEach((ccns, pid) => {
  if (ccns.size > 1 && !allowMulti.has(pid)) {
    const p = providers.get(pid);
    err(`Provider ${pid} (${p ? p.name : '?'}) has ${ccns.size} approved CCNs (${[...ccns].join(', ')}). A Provider record holds one address. Re-run with --allow-multi ${pid} if this is genuinely a multi-location record.`);
  }
});

// 7. rejected / needs_research are never accepted
const leaked = rows.filter((r) => ['reject', 'needs_research'].includes((r.reviewDecision || '').trim()) && approved.includes(r));
if (leaked.length) err(`${leaked.length} row(s) counted as accepted despite a reject/needs_research decision`);

// ---- report ---------------------------------------------------------------
const counts = rows.reduce((a, r) => { const d = (r.reviewDecision || '').trim() || '(blank)'; a[d] = (a[d] || 0) + 1; return a; }, {});
console.log(`file            : ${path.relative(ROOT, file)}`);
console.log(`rows            : ${rows.length}`);
console.log(`decisions       : ${Object.entries(counts).map(([k, v]) => `${k}=${v}`).join('  ')}`);
console.log(`would accept    : ${approved.length} identity row(s) across ${byProvider.size} provider(s)`);
console.log(`providers with no decision yet: ${new Set(rows.filter((r) => !(r.reviewDecision || '').trim()).map((r) => r.providerId)).size}`);
if (warnings.length) { console.log(''); warnings.forEach((w) => console.log(`WARN   ${w}`)); }
if (errors.length) {
  console.log('');
  errors.forEach((e) => console.log(`ERROR  ${e}`));
  console.log(`\nFAILED — ${errors.length} error(s). Do not import.`);
  process.exit(1);
}
console.log(`\nPASSED — safe to import ${approved.length} identity row(s).`);
