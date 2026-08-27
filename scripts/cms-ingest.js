#!/usr/bin/env node
/**
 * Normalize the CMS Provider Data Catalog hospice datasets into one compact
 * artifact the site can query by state / city / ZIP.
 *
 * Read-only with respect to the site: it writes a single JSON file and touches
 * nothing else. Run `node scripts/cms-ingest.js --download` to refresh the raw
 * CSVs first; otherwise it reads whatever is already in reports/cms-raw/.
 *
 * Source: https://data.cms.gov/provider-data (Hospice datasets, refreshed
 * quarterly by CMS). CMS inclusion is a public data fact, NOT a commercial
 * relationship with Best Hospice - see PARTICIPATION note below.
 */
const fs = require('fs');
const path = require('path');

const RAW = path.join(__dirname, '..', 'reports', 'cms-raw');
const OUT = path.join(__dirname, '..', 'reports', 'cms-normalized.json');

// Dataset ids in the CMS Provider Data Catalog. Kept here so a refresh can
// re-resolve current download URLs from the metastore rather than hardcoding
// the dated file names, which change every quarter.
const DATASETS = {
  general: 'yc9t-dgbk',
  provider: '252m-zfp9',
  zip: '95rg-2usp',
  cahps_provider: 'gxki-hrr8',
  state: 'eda0-92f0',
  national: '3xeb-u9wp'
};

// ---- minimal CSV reader (quoted fields, embedded commas/newlines) ----------
function parseCSV(text) {
  const rows = [];
  let row = [], field = '', q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) {
      if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; }
      else field += c;
    } else if (c === '"') q = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field); field = ''; rows.push(row); row = []; }
    else if (c !== '\r') field += c;
  }
  if (field.length || row.length) { row.push(field); rows.push(row); }
  const header = rows.shift().map((h) => h.replace(/^﻿/, '').trim());
  return rows.filter((r) => r.length === header.length)
    .map((r) => Object.fromEntries(header.map((h, i) => [h, r[i]])));
}

const read = (name) => parseCSV(fs.readFileSync(path.join(RAW, name + '.csv'), 'utf8'));

// CMS writes the literal string "Not Available" when a measure is suppressed
// or the provider has too few cases. Treat that as absent, never as zero.
const NA = new Set(['Not Available', 'Not Applicable', '', 'N/A']);
const num = (v) => {
  if (v == null || NA.has(String(v).trim())) return null;
  // The 2026-08-19 release began writing percentage scores with a trailing '%'
  // in state.csv ('55.7%') where the previous release wrote '55.7'. Strip that
  // and thousands separators, or every state percentage benchmark silently
  // becomes null and the page renders "not reported" for data we have.
  const n = Number(String(v).replace(/,/g, '').replace(/%\s*$/, '').trim());
  return Number.isFinite(n) ? n : null;
};
const str = (v) => (v == null || NA.has(String(v).trim()) ? null : String(v).trim());

// Measures worth surfacing to a family, with plain-language labels. Anything
// not listed here is ingested but not promoted to the page.
const MEASURES = {
  H_012_00_OBSERVED: { key: 'hciOverall', label: 'Hospice Care Index overall score', unit: 'score', better: 'high', max: 10 },
  H_011_01_OBSERVED: { key: 'visitsLastDays', label: 'Visits in the last days of life', unit: '%', better: 'high' },
  H_008_01_OBSERVED: { key: 'compositeProcess', label: 'Composite quality-of-care process measure', unit: '%', better: 'high' },
  H_012_02_OBSERVED: { key: 'nursingGaps', label: 'Gaps in nursing visits', unit: '%', better: 'low' },
  H_012_03_OBSERVED: { key: 'earlyDischarge', label: 'Early live discharges', unit: '%', better: 'low' },
  H_012_10_OBSERVED: { key: 'visitsNearDeath', label: 'Visits near death', unit: '%', better: 'high' },
  H_012_08_OBSERVED: { key: 'nurseMinutes', label: 'Nurse minutes per routine home care day', unit: 'min', better: 'high' },
  H_012_09_OBSERVED: { key: 'weekendNursing', label: 'Skilled nursing minutes on weekends', unit: '%', better: 'high' },
  Provided_Home_Care_only: { key: 'routineHomeCareOnly', label: 'Provides routine home care only', unit: 'yesno' }
};
const CAHPS = {
  SUMMARY_STAR_RATING: { key: 'starRating', label: 'Family caregiver survey star rating', unit: 'stars' },
  RECOMMEND_TBV: { key: 'wouldRecommend', label: 'Would definitely recommend this hospice', unit: '%' },
  RATING_TBV: { key: 'overallRating9to10', label: 'Rated the hospice 9 or 10 out of 10', unit: '%' },
  TEAM_COMM_TBV: { key: 'teamCommunication', label: 'Hospice team communicated well', unit: '%' },
  TIMELY_CARE_TBV: { key: 'timelyCare', label: 'Received timely help', unit: '%' },
  SYMPTOMS_TBV: { key: 'symptomHelp', label: 'Got help for pain and symptoms', unit: '%' },
  RESPECT_TBV: { key: 'treatedWithRespect', label: 'Patient treated with respect', unit: '%' },
  EMO_REL_TBV: { key: 'emotionalSupport', label: 'Emotional and spiritual support', unit: '%' }
};

function build() {
  const gen = read('general');
  const hospices = {};
  for (const g of gen) {
    const ccn = g['CMS Certification Number (CCN)'];
    hospices[ccn] = {
      ccn,
      name: str(g['Facility Name']),
      address: [str(g['Address Line 1']), str(g['Address Line 2'])].filter(Boolean).join(', '),
      city: str(g['City/Town']),
      state: str(g['State']),
      zip: (str(g['ZIP Code']) || '').slice(0, 5),
      county: str(g['County/Parish']),
      phone: str(g['Telephone Number']),
      ownership: str(g['Ownership Type']),
      certified: str(g['Certification Date']),
      // PARTICIPATION: always false here. Presence in CMS data says nothing
      // about whether an organization subscribes to Best Hospice.
      bestHospiceParticipating: false,
      measures: {}, cahps: {}, servesZips: []
    };
  }

  let period = null;
  for (const r of read('provider')) {
    const m = MEASURES[r['Measure Code']];
    const h = hospices[r['CMS Certification Number (CCN)']];
    if (!m || !h) continue;
    if (r['Measure Code'] === 'H_012_00_OBSERVED') period = str(r['Measure Date Range']) || period;
    h.measures[m.key] = m.unit === 'yesno' ? str(r['Score']) : num(r['Score']);
    if (h.measures[m.key] === null) delete h.measures[m.key];
  }
  for (const r of read('cahps_provider')) {
    const m = CAHPS[r['Measure Code']];
    const h = hospices[r['CMS Certification Number (CCN)']];
    if (!m || !h) continue;
    const v = m.unit === 'stars' ? num(r['Star Rating']) : num(r['Score']);
    if (v !== null) h.cahps[m.key] = v;
  }
  for (const r of read('zip')) {
    const h = hospices[r['CMS Certification Number (CCN)']];
    if (h) h.servesZips.push((r['ZIP Code'] || '').trim().slice(0, 5));
  }

  const benchmarks = { national: {}, state: {} };
  for (const r of read('national')) {
    const m = MEASURES[r['Measure Code']];
    if (m) benchmarks.national[m.key] = num(r['Score']);
  }
  for (const r of read('state')) {
    const m = MEASURES[r['Measure Code']];
    if (!m) continue;
    const st = str(r['State']);
    if (!st) continue;
    (benchmarks.state[st] = benchmarks.state[st] || {})[m.key] = num(r['Score']);
  }

  // ZIP -> city index, derived from CMS provider addresses. LIMITATION: this
  // only knows ZIPs that contain at least one hospice, so city service-area
  // counts are a floor, not a complete count. A full national rollout needs a
  // real ZIP/place crosswalk.
  const zipCity = {};
  for (const h of Object.values(hospices)) {
    if (h.zip && h.city && h.state) {
      (zipCity[h.zip] = zipCity[h.zip] || []).push(`${h.city.toUpperCase()}|${h.state.toUpperCase()}`);
    }
  }
  return { generated: new Date().toISOString(), measurePeriod: period, hospices, benchmarks, zipCity,
           labels: { measures: MEASURES, cahps: CAHPS } };
}

if (require.main === module) {
  const data = build();
  fs.writeFileSync(OUT, JSON.stringify(data));
  const n = Object.keys(data.hospices).length;
  const withHci = Object.values(data.hospices).filter((h) => h.measures.hciOverall != null).length;
  const withStar = Object.values(data.hospices).filter((h) => h.cahps.starRating != null).length;
  console.log(`normalized ${n} Medicare-certified hospices -> ${path.relative(process.cwd(), OUT)}`);
  console.log(`  measure period: ${data.measurePeriod}`);
  console.log(`  Hospice Care Index score: ${withHci} (${(withHci / n * 100).toFixed(1)}%)`);
  console.log(`  CAHPS star rating:        ${withStar} (${(withStar / n * 100).toFixed(1)}%)`);
  console.log(`  state benchmark rows:     ${Object.keys(data.benchmarks.state).length}`);
}
module.exports = { build };
