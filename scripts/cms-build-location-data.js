#!/usr/bin/env node
/**
 * Precompute the CMS summary a location page renders, for an explicit list of
 * places, into a small committed artifact.
 *
 * Why precompute: the normalized CMS artifact is ~6 MB and lives in gitignored
 * reports/, so production cannot read it. Rather than shipping 6 MB or fetching
 * at runtime, this emits only the numbers the page actually shows, only for
 * places we have deliberately enabled. Regenerate after each CMS release.
 *
 *   node scripts/cms-build-location-data.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const SRC = path.join(ROOT, 'reports', 'cms-normalized.json');
const OUT = path.join(ROOT, 'data', 'cms-location-summary.json');

// Places enabled for CMS enrichment, keyed exactly as they appear in the URL.
// Adding a place here is a deliberate act: it puts new content on a live,
// indexed page. Start small and measure.
const ENABLED = [
  { key: 'hospice-care/tucson-az', scope: 'city', city: 'TUCSON', state: 'AZ', label: 'Tucson, Arizona' }
];

const data = JSON.parse(fs.readFileSync(SRC, 'utf8'));
const H = Object.values(data.hospices);
const avg = (xs) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);
const r1 = (v) => (v == null ? null : Math.round(v * 10) / 10);

function cohort(p) {
  if (p.scope === 'state') return H.filter((h) => h.state === p.state);
  const located = H.filter((h) => h.city === p.city && h.state === p.state);
  const zips = new Set(located.map((h) => h.zip).filter(Boolean));
  const seen = new Set(located.map((h) => h.ccn));
  // CMS service-area ZIPs are self-reported, so restrict to in-state; an
  // agency hundreds of miles away must not read as a local option.
  const serving = H.filter((h) => !seen.has(h.ccn) && h.state === p.state && h.servesZips.some((z) => zips.has(z)));
  return { located, all: located.concat(serving) };
}

const out = { generated: new Date().toISOString(), measurePeriod: data.measurePeriod, places: {} };

for (const p of ENABLED) {
  const { located, all } = cohort(p);
  const hci = all.map((h) => h.measures.hciOverall).filter((v) => v != null);
  const vld = all.map((h) => h.measures.visitsLastDays).filter((v) => v != null);
  const rated = all.filter((h) => h.cahps.starRating != null)
    .sort((a, b) => (located.includes(b) - located.includes(a))
      || b.cahps.starRating - a.cahps.starRating
      || (b.cahps.wouldRecommend || 0) - (a.cahps.wouldRecommend || 0));
  const own = all.reduce((m, h) => { const k = h.ownership || 'Not reported to CMS'; m[k] = (m[k] || 0) + 1; return m; }, {});
  const sb = data.benchmarks.state[p.state] || {};
  const nb = data.benchmarks.national;

  out.places[p.key] = {
    label: p.label,
    state: p.state,
    cohortSize: all.length,
    basedHere: located.length,
    routineHomeCareOnly: all.filter((h) => h.measures.routineHomeCareOnly === 'Yes').length,
    levelsReported: all.filter((h) => h.measures.routineHomeCareOnly != null).length,
    hciLocal: r1(avg(hci)), hciCount: hci.length,
    hciState: r1(sb.hciOverall), hciNational: r1(nb.hciOverall),
    vldLocal: r1(avg(vld)), vldCount: vld.length,
    vldState: r1(sb.visitsLastDays), vldNational: r1(nb.visitsLastDays),
    ownership: Object.entries(own).sort((a, b) => b[1] - a[1]).map(([k, v]) => ({ type: k, n: v })),
    ratedCount: rated.length,
    // Top-rated by CAHPS. These are CMS records, never participating providers.
    topRated: rated.slice(0, 8).map((h) => ({
      name: h.name, city: h.city, state: h.state, ownership: h.ownership,
      star: h.cahps.starRating, recommend: h.cahps.wouldRecommend,
      hci: r1(h.measures.hciOverall), local: located.includes(h)
    }))
  };
}

fs.mkdirSync(path.dirname(OUT), { recursive: true });
fs.writeFileSync(OUT, JSON.stringify(out, null, 2));
const bytes = fs.statSync(OUT).size;
console.log(`wrote ${path.relative(ROOT, OUT)} (${(bytes / 1024).toFixed(1)} KB) for ${Object.keys(out.places).length} place(s)`);
for (const [k, v] of Object.entries(out.places)) {
  console.log(`  ${k}: ${v.cohortSize} hospices (${v.basedHere} based there), ${v.ratedCount} rated, ${v.routineHomeCareOnly}/${v.levelsReported} routine-home-care-only`);
  console.log(`     HCI local ${v.hciLocal} / ${v.state} ${v.hciState} / US ${v.hciNational}   visits ${v.vldLocal}% / ${v.vldState}% / ${v.vldNational}%`);
}
