#!/usr/bin/env node
/**
 * Renders the proposed CMS enrichment block for the pilot pages so it can be
 * judged as a product, not just as an integration. Writes standalone HTML
 * previews to reports/cms-pilot/. Does not touch any live page.
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const data = JSON.parse(fs.readFileSync(path.join(ROOT, 'reports', 'cms-normalized.json'), 'utf8'));
const bhAll = JSON.parse(fs.readFileSync(path.join(ROOT, 'reports', 'cms-raw', 'bh-providers.json'), 'utf8')).providers;
const H = Object.values(data.hospices);
const OUT = path.join(ROOT, 'reports', 'cms-pilot');
fs.mkdirSync(OUT, { recursive: true });

const esc = (s) => String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const title = (s) => String(s || '').toLowerCase().replace(/\b[a-z]/g, (c) => c.toUpperCase());
const avg = (xs) => (xs.length ? xs.reduce((a, b) => a + b, 0) / xs.length : null);
const n1 = (v, u = '') => (v == null ? '<span class="na">not reported</span>' : v.toFixed(1) + u);

const PILOT = {
  'salem-or':     { scope: 'city',  city: 'SALEM',     state: 'OR', label: 'Salem, Oregon',    role: 'strongest existing opportunity (202 impressions, position 12.6)' },
  'ut':           { scope: 'state', state: 'UT',       label: 'Utah',                          role: 'highest-volume location page (1,200 impressions, position 41.7)' },
  'las-vegas-nv': { scope: 'city',  city: 'LAS VEGAS', state: 'NV', label: 'Las Vegas, Nevada',role: 'zero Best Hospice providers (not currently in sitemap)' },
  'atlanta-ga':   { scope: 'city',  city: 'ATLANTA',   state: 'GA', label: 'Atlanta, Georgia', role: 'one-provider market (41 impressions, position 12.8)' },
  'phoenix-az':   { scope: 'city',  city: 'PHOENIX',   state: 'AZ', label: 'Phoenix, Arizona', role: 'multi-provider market (396 impressions, position 55.5)' }
};

function cohort(p) {
  if (p.scope === 'state') return H.filter((h) => h.state === p.state);
  const located = H.filter((h) => h.city === p.city && h.state === p.state);
  const zips = new Set(located.map((h) => h.zip).filter(Boolean));
  const seen = new Set(located.map((h) => h.ccn));
  // CMS service-area ZIPs are self-reported; keep in-state matches only so a
  // distant multi-state agency cannot present itself as a local option.
  const serving = H.filter((h) => !seen.has(h.ccn) && h.state === p.state && h.servesZips.some((z) => zips.has(z)));
  return located.concat(serving);
}

function block(key, p) {
  const c = cohort(p);
  const place = p.label;
  const bh = bhAll.filter((x) => (x.state || '').toUpperCase() === p.state &&
    (p.scope === 'state' || (x.city || '').toUpperCase() === p.city));
  const sb = data.benchmarks.state[p.state] || {};
  const nb = data.benchmarks.national;

  const own = c.reduce((m, h) => { const k = h.ownership || 'Not reported to CMS'; m[k] = (m[k] || 0) + 1; return m; }, {});
  const rhcOnly = c.filter((h) => h.measures.routineHomeCareOnly === 'Yes').length;
  // Hospices physically in the place come first: CMS service-area ZIPs are
  // self-reported, so an agency 400 miles away can legitimately appear in the
  // cohort and would read as a local option if we ranked purely on rating.
  const isLocal = (h) => p.scope === 'state' || h.city === p.city;
  const rated = c.filter((h) => h.cahps.starRating != null)
    .sort((a, b) => (isLocal(b) - isLocal(a))
      || b.cahps.starRating - a.cahps.starRating
      || (b.cahps.wouldRecommend || 0) - (a.cahps.wouldRecommend || 0));
  const stateCol = p.scope !== 'state';
  const hci = c.map((h) => h.measures.hciOverall).filter((v) => v != null);
  const vld = c.map((h) => h.measures.visitsLastDays).filter((v) => v != null);

  const ownRows = Object.entries(own).sort((a, b) => b[1] - a[1])
    .map(([k, v]) => `<tr><td>${esc(k)}</td><td class="num">${v}</td><td class="num">${(v / c.length * 100).toFixed(0)}%</td></tr>`).join('');

  const ratedRows = rated.slice(0, 10).map((h) => `<tr>
      <td>${esc(title(h.name))}<div class="sub">${esc(title(h.city))}, ${esc(h.state)} &middot; ${esc(h.ownership || 'ownership not reported')}</div></td>
      <td class="num">${h.cahps.starRating}/5</td>
      <td class="num">${h.cahps.wouldRecommend == null ? '&mdash;' : h.cahps.wouldRecommend + '%'}</td>
      <td class="num">${h.measures.hciOverall == null ? '&mdash;' : h.measures.hciOverall.toFixed(1)}</td>
    </tr>`).join('');

  const bhRows = bh.length ? bh.map((x) => {
    const match = H.find((h) => h.name && x.name && h.name.toUpperCase().includes(String(x.name).toUpperCase().slice(0, 14)) && h.state === p.state);
    return `<tr><td>${esc(x.name)}<div class="sub">${esc(title(x.city || ''))}, ${esc((x.state || '').toUpperCase())}</div></td>
      <td class="num">${match && match.cahps.starRating != null ? match.cahps.starRating + '/5' : '&mdash;'}</td>
      <td class="num">${match && match.measures.hciOverall != null ? match.measures.hciOverall.toFixed(1) : '&mdash;'}</td></tr>`;
  }).join('') : `<tr><td colspan="3" class="empty">Best Hospice does not yet have a participating provider in ${esc(place)}. The CMS information below is provided so families can still research their local options.</td></tr>`;

  return `<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>CMS pilot preview &mdash; ${esc(place)}</title>
<style>
 body{font:16px/1.6 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#0f172a;background:#f8fafc;margin:0;padding:28px}
 .wrap{max-width:860px;margin:0 auto}
 .role{background:#0f766e;color:#fff;padding:8px 14px;border-radius:6px;font-size:.82em;display:inline-block;margin-bottom:18px}
 .card{background:#fff;border-radius:12px;padding:22px;margin-bottom:16px;box-shadow:0 1px 3px rgba(15,23,42,.08)}
 h1{font-size:1.5em;margin:0 0 6px} h2{font-size:1.15em;margin:0 0 10px} h3{font-size:1em;margin:18px 0 8px}
 table{width:100%;border-collapse:collapse;margin:10px 0;font-size:.94em}
 th,td{text-align:left;padding:8px 10px;border-bottom:1px solid #e2e8f0;vertical-align:top}
 th{font-size:.8em;text-transform:uppercase;letter-spacing:.04em;color:#64748b}
 td.num,th.num{text-align:right;white-space:nowrap} .sub{font-size:.84em;color:#64748b}
 .na{color:#94a3b8;font-style:italic} .empty{color:#64748b;font-style:italic}
 .stat{display:flex;gap:22px;flex-wrap:wrap;margin:6px 0 2px}
 .stat div{flex:1;min-width:130px} .stat b{display:block;font-size:1.7em;line-height:1.15;color:#0f766e}
 .stat span{font-size:.84em;color:#64748b}
 .note{font-size:.85em;color:#64748b;margin-top:10px}
 .warn{background:#fef7ec;border-left:3px solid #d97706;padding:10px 14px;border-radius:0 6px 6px 0;font-size:.9em;margin:12px 0}
 .sep{background:#f1f5f9;border-left:3px solid #0f766e;padding:10px 14px;border-radius:0 6px 6px 0;font-size:.9em;margin:12px 0}
 a{color:#0f766e}
</style></head><body><div class="wrap">
<div class="role">PILOT PREVIEW &mdash; ${esc(p.role)}</div>
<h1>Hospice Care in ${esc(place)}</h1>
<p class="note">Everything below is generated from the current CMS hospice datasets (measure period ${esc(data.measurePeriod)}). Nothing here is written by hand per page.</p>

<div class="card">
  <h2>The hospice market in ${esc(place)}</h2>
  <div class="stat">
    <div><b>${c.length}</b><span>Medicare-certified hospices serving this area</span></div>
    <div><b>${rated.length}</b><span>with published family-survey ratings</span></div>
    <div><b>${rhcOnly}</b><span>offer routine home care only</span></div>
    <div><b>${bh.length}</b><span>Best Hospice participating providers</span></div>
  </div>
  ${rhcOnly ? `<div class="warn"><strong>Worth asking about:</strong> ${rhcOnly} of the ${c.length} hospices serving ${esc(place)} reported providing <em>only</em> routine home care during the measure period &mdash; meaning no continuous home care during a crisis and no general inpatient care. If symptoms become hard to manage at home, that limits your options. Ask any hospice directly which levels of care they staff.</div>` : ''}
</div>

<div class="card">
  <h2>How ${esc(place)} compares</h2>
  <table><thead><tr><th>Measure</th><th class="num">${esc(place)}</th>${stateCol ? `<th class="num">${esc(p.state)} average</th>` : ''}<th class="num">U.S. average</th></tr></thead><tbody>
   <tr><td>Hospice Care Index (0&ndash;10, higher is better)<div class="sub">CMS composite of ten care indicators</div></td><td class="num">${n1(avg(hci))}</td>${stateCol ? `<td class="num">${n1(sb.hciOverall)}</td>` : ''}<td class="num">${n1(nb.hciOverall)}</td></tr>
   <tr><td>Visits in the last days of life<div class="sub">% of patients visited by a nurse or social worker in their final days</div></td><td class="num">${n1(avg(vld), '%')}</td>${stateCol ? `<td class="num">${n1(sb.visitsLastDays, '%')}</td>` : ''}<td class="num">${n1(nb.visitsLastDays, '%')}</td></tr>
  </tbody></table>
  <p class="note">Local figures are the average across the ${c.length} hospices serving ${esc(place)}; ${hci.length} of them have a published Hospice Care Index score and ${vld.length} have a published visits measure.</p>
</div>

<div class="card">
  <h2>Ownership of hospices serving ${esc(place)}</h2>
  <table><thead><tr><th>Ownership type</th><th class="num">Hospices</th><th class="num">Share</th></tr></thead><tbody>${ownRows}</tbody></table>
  <p class="note">Ownership type is reported by each hospice to CMS. It is not a quality measure, but families often want to know it.</p>
</div>

<div class="card">
  <h2>Best Hospice participating providers in ${esc(place)}</h2>
  <div class="sep">${bh.length
    ? `${bh.length === 1 ? 'This is the one provider' : `These are the ${bh.length} providers`} that participate${bh.length === 1 ? 's' : ''} in Best Hospice and can receive a referral through this site.`
    : `Best Hospice has no participating provider in ${esc(place)} yet, so there is no one here to refer you to through this site.`}</div>
  <table><thead><tr><th>Provider</th><th class="num">Family survey</th><th class="num">Care Index</th></tr></thead><tbody>${bhRows}</tbody></table>
</div>

<div class="card">
  <h2>All Medicare-certified hospices serving ${esc(place)}</h2>
  <div class="sep"><strong>These are not Best Hospice providers.</strong> The list below comes entirely from public CMS data. Appearing here does not mean an organization participates in Best Hospice, is verified by us, or is recommended by us. We show it so you can research every option in your area, including ones we have no relationship with.</div>
  ${rated.length ? `<table><thead><tr><th>Hospice (CMS data)</th><th class="num">Family survey</th><th class="num">Would recommend</th><th class="num">Care Index</th></tr></thead><tbody>${ratedRows}</tbody></table>
  <p class="note">Showing ${Math.min(10, rated.length)} of the ${c.length} hospices with a published CAHPS star rating, those based in ${esc(place)} first. ${c.length - rated.length} hospices serving ${esc(place)} have no published rating &mdash; usually because they had too few surveyed families to report, which is common for smaller and newer agencies. A missing rating is not a bad rating.</p>`
  : `<p class="empty">None of the ${c.length} hospices serving ${esc(place)} have a published CAHPS family-survey rating for this measure period.</p>`}
</div>

<div class="card">
  <h2>Where this information comes from</h2>
  <p class="note">Hospice identification, location, ownership, certification, quality measures, the Hospice Care Index, and family-survey results on this page come from the
   <a href="https://data.cms.gov/provider-data" rel="nofollow noopener" target="_blank">CMS Provider Data Catalog</a> hospice datasets, measure period ${esc(data.measurePeriod)}.
   Service areas reflect the ZIP codes each hospice reports to CMS, which is self-reported and can include areas far from where a hospice is based &mdash; check the city shown for each one. CMS refreshes these datasets quarterly.</p>
  <p class="note">Best Hospice and Home Health is an independent directory. We are not affiliated with, endorsed by, or acting on behalf of Medicare, CMS, or any U.S. government agency. Quality measures describe past reporting periods and may not reflect current care. This is general information, not medical advice.</p>
</div>
</div></body></html>`;
}

for (const [key, p] of Object.entries(PILOT)) {
  const f = path.join(OUT, key + '.html');
  fs.writeFileSync(f, block(key, p));
  console.log('wrote', path.relative(ROOT, f));
}
