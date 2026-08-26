#!/usr/bin/env node
/**
 * Five-page CMS enrichment pilot. For each pilot page, reports exactly what
 * CMS data is available - and what is missing - so we can judge whether the
 * page becomes genuinely more useful, not just longer.
 *
 * Read-only. Prints a report; writes nothing to the site.
 */
const fs = require('fs');
const path = require('path');

const data = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'reports', 'cms-normalized.json'), 'utf8'));
const bh = JSON.parse(fs.readFileSync(path.join(__dirname, '..', 'reports', 'cms-raw', 'bh-providers.json'), 'utf8')).providers;
const H = Object.values(data.hospices);

const PILOT = [
  { url: '/hospice-care/salem-or',    role: 'strongest existing opportunity', scope: 'city',  city: 'SALEM',     state: 'OR', imp: 202,  pos: 12.6 },
  { url: '/hospice-care/ut',          role: 'Utah (highest-volume location page)', scope: 'state',              state: 'UT', imp: 1200, pos: 41.7 },
  { url: '/hospice-care/las-vegas-nv',role: 'zero Best Hospice providers',    scope: 'city',  city: 'LAS VEGAS', state: 'NV', imp: 0,    pos: null },
  { url: '/hospice-care/atlanta-ga',  role: 'one-provider market',            scope: 'city',  city: 'ATLANTA',   state: 'GA', imp: 41,   pos: 12.8 },
  { url: '/hospice-care/phoenix-az',  role: 'multi-provider market (richest)',scope: 'city',  city: 'PHOENIX',   state: 'AZ', imp: 396,  pos: 55.5 }
];

const pct = (a, b) => (b ? (a / b * 100).toFixed(0) + '%' : '-');

function cohort(p) {
  if (p.scope === 'state') return H.filter((h) => h.state === p.state);
  const located = H.filter((h) => h.city === p.city && h.state === p.state);
  const zips = new Set(located.map((h) => h.zip).filter(Boolean));
  const serving = zips.size ? H.filter((h) => h.servesZips.some((z) => zips.has(z))) : [];
  const seen = new Set(located.map((h) => h.ccn));
  return located.concat(serving.filter((h) => !seen.has(h.ccn)));
}

function bhCount(p) {
  return bh.filter((x) => (x.state || '').toUpperCase() === p.state &&
    (p.scope === 'state' || (x.city || '').toUpperCase() === p.city)).length;
}

const avg = (xs) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);

console.log('CMS ENRICHMENT PILOT - five pages\n');
console.log(`CMS universe: ${H.length} Medicare-certified hospices | measure period ${data.measurePeriod}`);
console.log('Best Hospice participating providers: ' + bh.length + '\n');

for (const p of PILOT) {
  const c = cohort(p);
  const n = c.length;
  const hci = c.map((h) => h.measures.hciOverall).filter((v) => v != null);
  const star = c.map((h) => h.cahps.starRating).filter((v) => v != null);
  const rec = c.map((h) => h.cahps.wouldRecommend).filter((v) => v != null);
  const vld = c.map((h) => h.measures.visitsLastDays).filter((v) => v != null);
  const own = c.reduce((m, h) => { const k = h.ownership || 'Unreported'; m[k] = (m[k] || 0) + 1; return m; }, {});
  const rhcOnly = c.filter((h) => h.measures.routineHomeCareOnly === 'Yes').length;
  const sb = data.benchmarks.state[p.state] || {};
  const nb = data.benchmarks.national;

  console.log('='.repeat(74));
  console.log(`${p.url}   [${p.role}]`);
  console.log(`  search today: ${p.imp} impressions${p.pos ? ', avg position ' + p.pos : ' (not in sitemap)'}`);
  console.log(`  Best Hospice participating providers here: ${bhCount(p)}`);
  console.log(`  CMS hospices in scope: ${n}`);
  if (!n) { console.log('  -> no CMS cohort; enrichment not possible\n'); continue; }
  console.log(`  data availability within cohort:`);
  console.log(`      Hospice Care Index score      ${String(hci.length).padStart(4)} / ${n}  (${pct(hci.length, n)})`);
  console.log(`      CAHPS star rating             ${String(star.length).padStart(4)} / ${n}  (${pct(star.length, n)})`);
  console.log(`      Would-recommend %             ${String(rec.length).padStart(4)} / ${n}  (${pct(rec.length, n)})`);
  console.log(`      Visits in last days of life   ${String(vld.length).padStart(4)} / ${n}  (${pct(vld.length, n)})`);
  console.log(`  local vs state vs national:`);
  const cmp = (label, local, s, nat, unit) => console.log(
    `      ${label.padEnd(30)} local ${local == null ? '  n/a' : local.toFixed(1).padStart(5)}${unit}   ${p.state} ${s == null ? ' n/a' : s.toFixed(1).padStart(5)}${unit}   US ${nat == null ? ' n/a' : nat.toFixed(1).padStart(5)}${unit}`);
  cmp('Hospice Care Index (0-10)', avg(hci), sb.hciOverall, nb.hciOverall, '');
  cmp('Visits in last days of life', avg(vld), sb.visitsLastDays, nb.visitsLastDays, '%');
  console.log(`  ownership mix: ` + Object.entries(own).sort((a, b) => b[1] - a[1]).map(([k, v]) => `${k} ${v}`).join(', '));
  console.log(`  offer only routine home care (no inpatient/continuous): ${rhcOnly} of ${n}`);
  if (star.length) {
    const top = c.filter((h) => h.cahps.starRating != null).sort((a, b) => b.cahps.starRating - a.cahps.starRating).slice(0, 3);
    console.log('  highest family-survey ratings in cohort (CMS data, NOT Best Hospice participants):');
    top.forEach((h) => console.log(`      ${h.cahps.starRating}/5 stars  ${h.name} (${h.city}, ${h.state})`));
  }
  console.log('');
}
