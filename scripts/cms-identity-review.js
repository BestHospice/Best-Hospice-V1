#!/usr/bin/env node
/**
 * Build the human review artifact for CMS hospice identity candidates.
 *
 * Writes nothing to the database. The output is a decision sheet: a human
 * fills in reviewDecision, the validator checks it, and only then does any
 * future importer create ProviderExternalIdentity rows.
 *
 * One row per Provider-to-CMS candidate, not one row per provider. Alternates
 * are included so a reviewer can compare them side by side, because the
 * dangerous cases here are not "no candidate" but "several plausible ones".
 *
 * Rows are keyed on providerId, never on provider name: three distinct
 * Provider records are all called "Choice Hospice" and share one phone number.
 *
 * Deterministic by design - no timestamps, stable sort - so re-running after a
 * CMS refresh produces a file that diffs cleanly against the reviewed one.
 *
 *   node scripts/cms-identity-review.js
 */
const fs = require('fs');
const path = require('path');
const { CONFIDENCE, candidatesFor, providers } = require('./cms-match-candidates.js');

const ROOT = path.join(__dirname, '..');
const SOURCE = 'cms_hospice';
const IDENTIFIER_TYPE = 'ccn';

const eligible = providers.filter((p) => String(p.careType || '').toLowerCase() === 'hospice');

// Score every eligible provider first: contested detection needs the whole set.
const scored = eligible.map((p) => ({ p, cands: candidatesFor(p) }));

// One CMS certification belongs to one organization. If two Provider records
// both propose it, at least one is wrong - flag every affected row.
const claims = new Map();
scored.forEach(({ p, cands }) => {
  if (!cands.length) return;
  const ccn = cands[0].h.ccn;
  if (!claims.has(ccn)) claims.set(ccn, []);
  claims.get(ccn).push(p);
});
const contestedCcns = new Set([...claims].filter(([, ps]) => ps.length > 1).map(([c]) => c));

const label = (p) => `${p.name} (${p.city}, ${p.state}) [${p.id.slice(0, 8)}]`;

const rows = [];
for (const { p, cands } of scored) {
  const bestCcn = cands.length ? cands[0].h.ccn : '';
  const providerContested = bestCcn && contestedCcns.has(bestCcn);

  if (!cands.length) {
    rows.push({
      providerId: p.id, providerName: p.name, providerCity: p.city, providerState: p.state,
      providerPhone: p.phone || '', providerAddress: p.address || '',
      proposedCcn: '', cmsName: '', cmsCity: '', cmsState: '', cmsPhone: '', cmsAddress: '',
      confidence: '', matchMethod: '', proposedStatus: 'no_match',
      candidateRank: '', candidateCountForProvider: 0,
      contestedCcn: 'no', contestedWith: '',
      supporting: '', uncertainty: 'no in-state CMS hospice resembled this record',
      reviewDecision: '', reviewNotes: ''
    });
    continue;
  }

  cands.forEach((c, i) => {
    const isBest = i === 0;
    const ccn = c.h.ccn;
    const contested = contestedCcns.has(ccn);
    let status;
    if (!isBest) status = 'candidate_alternate';
    else if (contested) status = 'candidate_review';        // contested never auto-high
    else status = c.score >= CONFIDENCE.HIGH ? 'candidate_high' : 'candidate_review';

    rows.push({
      providerId: p.id, providerName: p.name, providerCity: p.city, providerState: p.state,
      providerPhone: p.phone || '', providerAddress: p.address || '',
      proposedCcn: ccn, cmsName: c.h.name, cmsCity: c.h.city, cmsState: c.h.state,
      cmsPhone: c.h.phone || '', cmsAddress: c.h.address || '',
      confidence: c.score.toFixed(2), matchMethod: c.method, proposedStatus: status,
      candidateRank: i + 1, candidateCountForProvider: cands.length,
      contestedCcn: contested ? 'yes' : 'no',
      contestedWith: contested ? (claims.get(ccn) || []).filter((o) => o.id !== p.id).map(label).join('; ') : '',
      supporting: c.reasons.join('; '), uncertainty: c.against.join('; '),
      reviewDecision: '', reviewNotes: ''
    });
  });
}

// Group by provider so alternates stay next to the candidate they compete with,
// then order groups by how much attention they need.
const GROUP_ORDER = { contested: 0, candidate_review: 1, candidate_high: 2, no_match: 3 };
const groupKeyFor = (id) => {
  const mine = rows.filter((r) => r.providerId === id);
  if (mine.some((r) => r.contestedCcn === 'yes')) return 'contested';
  const head = mine.find((r) => r.candidateRank === 1 || r.proposedStatus === 'no_match');
  return head ? head.proposedStatus : 'no_match';
};
const groupKey = new Map(eligible.map((p) => [p.id, groupKeyFor(p.id)]));
rows.sort((a, b) =>
  GROUP_ORDER[groupKey.get(a.providerId)] - GROUP_ORDER[groupKey.get(b.providerId)] ||
  a.providerName.localeCompare(b.providerName) ||
  a.providerCity.localeCompare(b.providerCity) ||
  a.providerId.localeCompare(b.providerId) ||
  (Number(a.candidateRank) || 0) - (Number(b.candidateRank) || 0)
);

const COLS = ['providerId','providerName','providerCity','providerState','providerPhone','providerAddress',
  'proposedCcn','cmsName','cmsCity','cmsState','cmsPhone','cmsAddress',
  'confidence','matchMethod','proposedStatus','candidateRank','candidateCountForProvider',
  'contestedCcn','contestedWith','supporting','uncertainty','reviewDecision','reviewNotes'];

// Every field is quoted. CCNs carry leading zeros and must survive as text -
// note that a spreadsheet may still coerce them on open; the JSON companion
// and the validator are the authority.
const esc = (v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
const csv = [COLS.join(','), ...rows.map((r) => COLS.map((c) => esc(r[c])).join(','))].join('\n') + '\n';
const csvPath = path.join(ROOT, 'reports', 'cms-hospice-identity-review.csv');
fs.writeFileSync(csvPath, csv);

const jsonPath = path.join(ROOT, 'reports', 'cms-hospice-identity-review.json');
fs.writeFileSync(jsonPath, JSON.stringify({
  source: SOURCE,
  identifierType: IDENTIFIER_TYPE,
  allowedReviewDecisions: ['approve', 'reject', 'needs_research', ''],
  note: 'reviewDecision is blank until a human decides. Blank is not approval.',
  providersRepresented: eligible.length,
  candidateRows: rows.length,
  contestedCcns: [...contestedCcns].sort(),
  rows
}, null, 2) + '\n');

console.log(`providers represented : ${eligible.length}`);
console.log(`candidate rows        : ${rows.length}`);
console.log(`contested CCNs        : ${contestedCcns.size} (${[...contestedCcns].sort().join(', ') || 'none'})`);
console.log(`no-match providers    : ${rows.filter((r) => r.proposedStatus === 'no_match').length}`);
console.log(`\nwrote ${path.relative(ROOT, csvPath)}`);
console.log(`wrote ${path.relative(ROOT, jsonPath)}`);
