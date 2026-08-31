#!/usr/bin/env node
/**
 * Produce CMS match *candidates* for Best Hospice providers. Deliberately does
 * not write anything: the output is a review queue, not a mapping.
 *
 * The objective is precision. A wrong match attaches another organization's
 * quality measures and family-survey results to a named business, so the cost
 * of a false positive is far higher than the cost of leaving a provider
 * unmatched.
 *
 *   node scripts/cms-match-candidates.js            summary
 *   node scripts/cms-match-candidates.js --csv      also write the review CSV
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const cms = JSON.parse(fs.readFileSync(path.join(ROOT, 'reports', 'cms-normalized.json'), 'utf8'));
const bh = JSON.parse(fs.readFileSync(path.join(ROOT, 'reports', 'cms-raw', 'bh-providers.json'), 'utf8')).providers;
const H = Object.values(cms.hospices);

// ---- normalization --------------------------------------------------------
const digits = (s) => String(s || '').replace(/\D/g, '').slice(-10);
const STOP = /\b(LLC|L L C|INC|INCORPORATED|LP|LLP|CORP|CORPORATION|CO|THE|OF|AND|A|AN|SERVICES?|CARE|GROUP|PLLC|PC)\b/g;
const normName = (s) => String(s || '').toUpperCase()
  .replace(/&/g, ' AND ').replace(/[^A-Z0-9 ]/g, ' ')
  .replace(STOP, ' ').replace(/\s+/g, ' ').trim();
const normStreet = (s) => String(s || '').toUpperCase()
  .replace(/[^A-Z0-9 ]/g, ' ')
  .replace(/\b(SUITE|STE|UNIT|APT|BLDG|BUILDING|FLOOR|FL|ROOM|RM)\b.*$/, '')
  .replace(/\b(STREET)\b/g, 'ST').replace(/\b(AVENUE)\b/g, 'AVE')
  .replace(/\b(ROAD)\b/g, 'RD').replace(/\b(DRIVE)\b/g, 'DR')
  .replace(/\b(BOULEVARD)\b/g, 'BLVD').replace(/\b(NORTH|SOUTH|EAST|WEST)\b/g, (m) => m[0])
  .replace(/\s+/g, ' ').trim();

// Similarity has to tolerate CMS using the full legal name where we hold the
// trading name: "AccentCare Hospice" against "ACCENTCARE HOSPICE & PALLIATIVE
// CARE OF TEXAS" is the same organization, but plain token overlap scores it
// 0.5 and would rank it below a same-phone record in another city. Containment
// (are one name's tokens wholly inside the other?) separates that case from
// "Choice Hospice" against "Passion Hospice", which shares only the word
// hospice and scores 0.5 on overlap too.
function nameSim(a, b) {
  const A = new Set(normName(a).split(' ').filter(Boolean));
  const B = new Set(normName(b).split(' ').filter(Boolean));
  if (!A.size || !B.size) return 0;
  let hit = 0;
  A.forEach((t) => { if (B.has(t)) hit++; });
  const overlap = hit / Math.max(A.size, B.size);
  const containment = hit / Math.min(A.size, B.size);
  // Full containment of the shorter name is strong evidence; otherwise fall
  // back to plain overlap.
  return containment >= 0.999 ? Math.max(overlap, 0.85) : overlap;
}

// ---- matching rules -------------------------------------------------------
// Deterministic rules key on a single unambiguous field. Probabilistic rules
// combine weaker signals and can never on their own reach `verified`.
const CONFIDENCE = { HIGH: 0.9, MEDIUM: 0.65, LOW: 0.4 };

function candidatesFor(p) {
  const st = String(p.state || '').toUpperCase();
  const phone = digits(p.phone);
  const zip = String(p.zip || '').slice(0, 5);
  const street = normStreet(String(p.address || '').split(',')[0]);
  const out = [];

  for (const h of H) {
    if (h.state !== st) continue;              // never cross a state line
    const reasons = [];
    const against = [];
    let method = null;
    let score = 0;

    if (phone && digits(h.phone) === phone) {
      method = 'exact_phone'; score = CONFIDENCE.HIGH;
      reasons.push('identical 10-digit phone');
    }

    const sameZip = zip && h.zip === zip;
    const sameStreet = street && normStreet(h.address) === street;
    if (sameStreet && sameZip) {
      if (!method) { method = 'exact_address'; score = CONFIDENCE.HIGH; }
      reasons.push('identical street and ZIP');
    }

    const sim = nameSim(p.name, h.name);
    const sameCity = String(p.city || '').toUpperCase() === h.city;
    if (sim >= 0.99 && sameCity) {
      if (!method) { method = 'exact_name_city'; score = Math.max(score, CONFIDENCE.MEDIUM); }
      reasons.push('normalized name identical, same city');
    } else if (sim >= 0.6) {
      if (!method) { method = 'fuzzy_name'; score = Math.max(score, CONFIDENCE.LOW); }
      reasons.push(`name similarity ${(sim * 100).toFixed(0)}%`);
    }

    if (!method) continue;

    if (sameZip) reasons.push('same ZIP'); else if (zip) against.push('different ZIP');
    if (sameCity) reasons.push('same city'); else against.push(`different city (${h.city})`);
    if (sim < 0.6) against.push(`names differ (${(sim * 100).toFixed(0)}% similar)`);
    if (method === 'fuzzy_name' && !sameCity) against.push('fuzzy name and different city');

    // A single weak signal is never enough. Corroboration raises confidence.
    const corroboration = [sameZip, sameCity, sim >= 0.6].filter(Boolean).length;
    if (method === 'exact_phone' && corroboration >= 2) score = 0.97;
    if (method === 'fuzzy_name' && corroboration <= 1) score = 0.25;

    // Address alone is not identity. Hospices share office buildings and suites,
    // and the first pass on this data produced two false positives that way:
    // "Arizona Care Hospice Prescott Area" matched QUALITY HOSPICE CARE at the
    // same street and ZIP with 25% name similarity, and "Choice Hospice"
    // matched PASSION HOSPICE at 50%. Both are co-tenants, not the same
    // organization. An address match with a disagreeing name is a review item.
    if (method === 'exact_address' && sim < 0.6) {
      score = Math.min(score, 0.55);
      against.push('address shared but organization names disagree; likely a co-tenant at the same building');
    }

    // A shared phone number is not identity either. All three "Vitalcaring
    // Hospice" locations matched TRADITIONS HEALTH in Chandler on phone alone,
    // at 0% name similarity and two of them in a different city. Answering
    // services, corporate switchboards and post-acquisition number reuse all
    // produce this. Phone only carries the day when the name agrees or the
    // location does.
    if (method === 'exact_phone' && sim < 0.4 && !sameCity) {
      score = Math.min(score, 0.5);
      against.push('phone shared but names and city both disagree; likely a shared or reassigned number');
    } else if (method === 'exact_phone' && sim < 0.4) {
      score = Math.min(score, 0.7);
      against.push('phone matches but organization names do not');
    }

    // A multi-location brand (AccentCare Dallas vs AccentCare Houston) scores
    // the same on name, so geography has to decide. A candidate in another
    // city never outranks one in the provider's own city.
    if (!sameCity) score -= 0.15;

    out.push({ h, method, score, sim, sameCity, reasons, against });
  }
  out.sort((a, b) => (b.sameCity - a.sameCity) || (b.score - a.score) || (b.sim - a.sim));
  return out;
}


// Exported so the identity-review generator reuses this scoring rather than
// reimplementing it. Two copies of the matching rules would drift, and a
// review file built from drifted rules is worse than no review file.
module.exports = { CONFIDENCE, nameSim, normName, normStreet, digits, candidatesFor, providers: bh, hospices: H };

// ---- run ------------------------------------------------------------------
if (require.main === module) runReport();

function runReport() {
  // Only hospice-typed providers are matched against CMS *hospice* data. Matching
  // a home-care agency here is a category error, not a near miss.
  const eligible = bh.filter((p) => String(p.careType || '').toLowerCase() === 'hospice');
  const ineligible = bh.filter((p) => String(p.careType || '').toLowerCase() !== 'hospice');

  const rows = [];
  const buckets = { high: [], review: [], none: [] };
  for (const p of eligible) {
    const cands = candidatesFor(p);
    const best = cands[0];
    let status;
    if (!best) status = 'no_match';
    else if (best.score >= CONFIDENCE.HIGH) status = 'candidate_high';
    else status = 'candidate_review';
    (status === 'candidate_high' ? buckets.high : status === 'no_match' ? buckets.none : buckets.review).push({ p, best, cands });
    rows.push({
      bhName: p.name, bhType: p.careType, bhCity: p.city, bhState: p.state,
      cmsName: best ? best.h.name : '', ccn: best ? best.h.ccn : '',
      cmsCity: best ? best.h.city : '',
      method: best ? best.method : '', confidence: best ? best.score.toFixed(2) : '',
      supporting: best ? best.reasons.join('; ') : '',
      uncertainty: best ? best.against.join('; ') : 'no in-state CMS hospice resembled this record',
      otherCandidates: best ? Math.max(0, cands.length - 1) : 0,
      proposedStatus: status
    });
  }

  // One CMS certification belongs to one organization at one location. If two
  // Best Hospice records both point at it, at least one is wrong.
  const ccnClaims = {};
  rows.forEach((r) => { if (r.ccn) (ccnClaims[r.ccn] = ccnClaims[r.ccn] || []).push(r.bhName); });
  const contested = Object.entries(ccnClaims).filter(([, names]) => names.length > 1);
  rows.forEach((r) => {
    if (r.ccn && ccnClaims[r.ccn].length > 1) {
      r.uncertainty = [r.uncertainty, `CCN also proposed for: ${ccnClaims[r.ccn].filter((n) => n !== r.bhName).join(', ')}`].filter(Boolean).join('; ');
      if (r.proposedStatus === 'candidate_high') r.proposedStatus = 'candidate_review';
    }
  });

  console.log(`Best Hospice providers: ${bh.length}`);
  console.log(`  eligible for CMS hospice matching (careType=hospice): ${eligible.length}`);
  console.log(`  not eligible (no CMS hospice dataset applies):        ${ineligible.length}`);
  console.log(`\nCandidates for the ${eligible.length} eligible providers:`);
  console.log(`  high confidence (>= ${CONFIDENCE.HIGH}) : ${buckets.high.length}`);
  console.log(`  needs review                : ${buckets.review.length}`);
  console.log(`  no match                    : ${buckets.none.length}`);
  if (contested.length) {
    console.log(`\ncontested CCNs (same CMS record proposed for more than one provider):`);
    contested.forEach(([ccn, names]) => console.log(`  CCN ${ccn} <- ${names.join(', ')}`));
  }
  const finalHigh = rows.filter((r) => r.proposedStatus === 'candidate_high').length;
  const finalReview = rows.filter((r) => r.proposedStatus === 'candidate_review').length;
  console.log(`\nafter contested-CCN demotion:  high ${finalHigh}, review ${finalReview}, none ${buckets.none.length}`);

  const show = (label, list) => {
    if (!list.length) return;
    console.log(`\n--- ${label} ---`);
    list.forEach(({ p, best, cands }) => {
      if (!best) { console.log(`  ${p.name} (${p.city}, ${p.state})\n     no in-state CMS hospice resembled this record`); return; }
      console.log(`  ${p.name} (${p.city}, ${p.state})`);
      console.log(`     -> ${best.h.name} (${best.h.city}) CCN ${best.h.ccn}`);
      console.log(`        ${best.method} @ ${best.score.toFixed(2)} | for: ${best.reasons.join('; ')}`);
      if (best.against.length) console.log(`        against: ${best.against.join('; ')}`);
      if (cands.length > 1) console.log(`        ${cands.length - 1} other in-state candidate(s)`);
    });
  };
  show('HIGH CONFIDENCE', buckets.high);
  show('NEEDS REVIEW', buckets.review);
  show('NO MATCH', buckets.none);

  if (process.argv.includes('--csv')) {
    const out = path.join(ROOT, 'reports', 'cms-match-candidates.csv');
    const cols = Object.keys(rows[0]);
    const esc = (v) => `"${String(v == null ? '' : v).replace(/"/g, '""')}"`;
    fs.writeFileSync(out, [cols.join(','), ...rows.map((r) => cols.map((c) => esc(r[c])).join(','))].join('\n'));
    console.log(`\nwrote ${path.relative(ROOT, out)} (${rows.length} rows)`);
  }

}
