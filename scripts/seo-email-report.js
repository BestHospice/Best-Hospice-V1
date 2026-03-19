#!/usr/bin/env node
/**
 * SEO Email Report — sends a formatted SEO update to jcoutland@besthospice.com
 * Scheduled: Monday & Thursday at 8am
 * Run manually: node scripts/seo-email-report.js
 */

require('dotenv').config({ path: require('path').join(__dirname, '..', '.env') });

const { google } = require('googleapis');
const https = require('https');
const path = require('path');
const fs = require('fs');

const KEY_FILE = path.join(__dirname, '..', 'best-hospice-seo-40ab22f23d70.json');
const SITE_URL = 'sc-domain:besthospice.com';
const TO_EMAIL = process.env.ADS_REPORT_TO_EMAIL || 'jcoutland@besthospice.com';
const FROM_EMAIL = process.env.SENDGRID_FROM_EMAIL || 'jcoutland@besthospice.com';
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY;
const REPORT_FILE = path.join(__dirname, '..', 'seo-report.json');

// ─── GSC Pull ────────────────────────────────────────────────────────────────

async function pullGSCSnapshot() {
  const auth = new google.auth.GoogleAuth({
    keyFile: KEY_FILE,
    scopes: ['https://www.googleapis.com/auth/webmasters.readonly'],
  });
  const client = await auth.getClient();
  const gsc = google.searchconsole({ version: 'v1', auth: client });

  const endDate = new Date();
  const startDate = new Date();
  startDate.setDate(endDate.getDate() - 28); // Last 28 days for recency
  const fmt = d => d.toISOString().split('T')[0];

  const [totalsRes, queryRes, pageRes] = await Promise.all([
    gsc.searchanalytics.query({ siteUrl: SITE_URL, requestBody: { startDate: fmt(startDate), endDate: fmt(endDate) } }),
    gsc.searchanalytics.query({ siteUrl: SITE_URL, requestBody: { startDate: fmt(startDate), endDate: fmt(endDate), dimensions: ['query'], rowLimit: 25 } }),
    gsc.searchanalytics.query({ siteUrl: SITE_URL, requestBody: { startDate: fmt(startDate), endDate: fmt(endDate), dimensions: ['page'], rowLimit: 10 } }),
  ]);

  const totals = totalsRes.data.rows?.[0] || { clicks: 0, impressions: 0, ctr: 0, position: 0 };
  const queries = queryRes.data.rows || [];
  const pages = pageRes.data.rows || [];

  queries.sort((a, b) => a.position - b.position);

  const quickWins = queries.filter(r => r.position >= 5 && r.position <= 20 && r.impressions > 3);
  const top10 = queries.filter(r => r.position < 10);

  return { totals, queries, pages, quickWins, top10, dateRange: { start: fmt(startDate), end: fmt(endDate) } };
}

// ─── Compare to last report ───────────────────────────────────────────────────

function loadPreviousReport() {
  try {
    if (fs.existsSync(REPORT_FILE)) {
      return JSON.parse(fs.readFileSync(REPORT_FILE, 'utf8'));
    }
  } catch (_) {}
  return null;
}

function delta(current, previous, key) {
  if (!previous) return '';
  const diff = current - previous;
  if (diff === 0) return ' (no change)';
  const sign = diff > 0 ? '+' : '';
  return ` (${sign}${typeof current === 'number' && key === 'position' ? diff.toFixed(1) : diff} vs last report)`;
}

// ─── Email HTML builder ───────────────────────────────────────────────────────

function buildEmailHtml(snapshot, prev) {
  const { totals, queries, pages, quickWins, top10, dateRange } = snapshot;
  const prevTotals = prev?.gscData?.summary;

  const prevClicks = prevTotals ? parseInt(prevTotals.totalClicks) : null;
  const prevImpressions = prevTotals ? parseInt(prevTotals.totalImpressions) : null;
  const prevPosition = prevTotals ? parseFloat(prevTotals.avgPosition) : null;

  const clickDelta = prevClicks !== null ? totals.clicks - prevClicks : 0;
  const clickDeltaStr = prevClicks !== null ? ` <span style="color:${clickDelta >= 0 ? '#16a34a' : '#dc2626'}">(${clickDelta >= 0 ? '+' : ''}${clickDelta})</span>` : '';
  const impDelta = prevImpressions !== null ? totals.impressions - prevImpressions : 0;
  const impDeltaStr = prevImpressions !== null ? ` <span style="color:${impDelta >= 0 ? '#16a34a' : '#dc2626'}">(${impDelta >= 0 ? '+' : ''}${impDelta})</span>` : '';
  const posDelta = prevPosition !== null ? totals.position - prevPosition : 0;
  const posDeltaStr = prevPosition !== null ? ` <span style="color:${posDelta <= 0 ? '#16a34a' : '#dc2626'}">(${posDelta <= 0 ? '' : '+'}${posDelta.toFixed(1)})</span>` : '';

  const topQueriesRows = queries.slice(0, 10).map(r => `
    <tr>
      <td style="padding:6px 10px; border-bottom:1px solid #f1f5f9;">${r.keys[0]}</td>
      <td style="padding:6px 10px; border-bottom:1px solid #f1f5f9; text-align:center;">${r.position.toFixed(1)}</td>
      <td style="padding:6px 10px; border-bottom:1px solid #f1f5f9; text-align:center;">${r.impressions}</td>
      <td style="padding:6px 10px; border-bottom:1px solid #f1f5f9; text-align:center;">${r.clicks}</td>
    </tr>`).join('');

  const topPagesRows = pages.slice(0, 5).map(r => `
    <tr>
      <td style="padding:6px 10px; border-bottom:1px solid #f1f5f9; font-size:12px;">${r.keys[0].replace('https://www.besthospice.com', '')}</td>
      <td style="padding:6px 10px; border-bottom:1px solid #f1f5f9; text-align:center;">${r.clicks}</td>
      <td style="padding:6px 10px; border-bottom:1px solid #f1f5f9; text-align:center;">${r.impressions}</td>
      <td style="padding:6px 10px; border-bottom:1px solid #f1f5f9; text-align:center;">${r.position.toFixed(1)}</td>
    </tr>`).join('');

  const quickWinsList = quickWins.length
    ? quickWins.slice(0, 5).map(r => `<li style="margin-bottom:6px;"><strong>"${r.keys[0]}"</strong> — position ${r.position.toFixed(1)}, ${r.impressions} impressions. Small content push could reach page 1.</li>`).join('')
    : '<li>No new quick wins detected this period.</li>';

  const now = new Date().toLocaleDateString('en-US', { weekday: 'long', year: 'numeric', month: 'long', day: 'numeric' });

  return `<!DOCTYPE html>
<html>
<head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"></head>
<body style="margin:0;padding:0;background:#f8fafc;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;color:#0f172a;">
  <div style="max-width:640px;margin:0 auto;padding:24px 16px;">

    <div style="background:#1d4ed8;border-radius:12px 12px 0 0;padding:24px 28px;">
      <p style="margin:0;color:rgba(255,255,255,0.7);font-size:13px;">${now}</p>
      <h1 style="margin:8px 0 0;color:#fff;font-size:22px;font-weight:700;">BestHospice.com SEO Report</h1>
      <p style="margin:6px 0 0;color:rgba(255,255,255,0.8);font-size:14px;">Last 28 days: ${dateRange.start} → ${dateRange.end}</p>
    </div>

    <div style="background:#fff;padding:24px 28px;border-left:1px solid #e2e8f0;border-right:1px solid #e2e8f0;">

      <h2 style="margin:0 0 16px;font-size:16px;color:#1e40af;">📊 Performance Summary</h2>
      <table style="width:100%;border-collapse:collapse;margin-bottom:24px;">
        <tr style="background:#f1f5f9;">
          <th style="padding:8px 10px;text-align:left;font-size:13px;color:#64748b;font-weight:600;">Metric</th>
          <th style="padding:8px 10px;text-align:center;font-size:13px;color:#64748b;font-weight:600;">Value</th>
          <th style="padding:8px 10px;text-align:center;font-size:13px;color:#64748b;font-weight:600;">vs Last Report</th>
        </tr>
        <tr>
          <td style="padding:10px;border-bottom:1px solid #f1f5f9;font-weight:600;">Total Clicks</td>
          <td style="padding:10px;border-bottom:1px solid #f1f5f9;text-align:center;font-size:18px;font-weight:700;color:#1d4ed8;">${totals.clicks}</td>
          <td style="padding:10px;border-bottom:1px solid #f1f5f9;text-align:center;">${clickDeltaStr || '—'}</td>
        </tr>
        <tr>
          <td style="padding:10px;border-bottom:1px solid #f1f5f9;font-weight:600;">Total Impressions</td>
          <td style="padding:10px;border-bottom:1px solid #f1f5f9;text-align:center;font-size:18px;font-weight:700;color:#1d4ed8;">${totals.impressions}</td>
          <td style="padding:10px;border-bottom:1px solid #f1f5f9;text-align:center;">${impDeltaStr || '—'}</td>
        </tr>
        <tr>
          <td style="padding:10px;border-bottom:1px solid #f1f5f9;font-weight:600;">Avg Position</td>
          <td style="padding:10px;border-bottom:1px solid #f1f5f9;text-align:center;font-size:18px;font-weight:700;color:#1d4ed8;">${totals.position.toFixed(1)}</td>
          <td style="padding:10px;border-bottom:1px solid #f1f5f9;text-align:center;">${posDeltaStr || '—'} <span style="font-size:11px;color:#94a3b8;">(lower = better)</span></td>
        </tr>
        <tr>
          <td style="padding:10px;font-weight:600;">Avg CTR</td>
          <td style="padding:10px;text-align:center;font-size:18px;font-weight:700;color:#1d4ed8;">${(totals.ctr * 100).toFixed(2)}%</td>
          <td style="padding:10px;text-align:center;">—</td>
        </tr>
      </table>

      <h2 style="margin:0 0 12px;font-size:16px;color:#1e40af;">🔑 Top Queries (by position)</h2>
      <table style="width:100%;border-collapse:collapse;margin-bottom:24px;font-size:13px;">
        <tr style="background:#f1f5f9;">
          <th style="padding:6px 10px;text-align:left;color:#64748b;">Query</th>
          <th style="padding:6px 10px;text-align:center;color:#64748b;">Pos</th>
          <th style="padding:6px 10px;text-align:center;color:#64748b;">Impr</th>
          <th style="padding:6px 10px;text-align:center;color:#64748b;">Clicks</th>
        </tr>
        ${topQueriesRows}
      </table>

      <h2 style="margin:0 0 12px;font-size:16px;color:#1e40af;">📄 Top Pages (by clicks)</h2>
      <table style="width:100%;border-collapse:collapse;margin-bottom:24px;font-size:13px;">
        <tr style="background:#f1f5f9;">
          <th style="padding:6px 10px;text-align:left;color:#64748b;">Page</th>
          <th style="padding:6px 10px;text-align:center;color:#64748b;">Clicks</th>
          <th style="padding:6px 10px;text-align:center;color:#64748b;">Impr</th>
          <th style="padding:6px 10px;text-align:center;color:#64748b;">Pos</th>
        </tr>
        ${topPagesRows}
      </table>

      <h2 style="margin:0 0 12px;font-size:16px;color:#1e40af;">🎯 Quick Win Opportunities</h2>
      <p style="margin:0 0 10px;font-size:13px;color:#64748b;">Keywords ranking positions 5–20 that are close to page 1:</p>
      <ul style="margin:0 0 24px;padding-left:20px;font-size:14px;line-height:1.6;">
        ${quickWinsList}
      </ul>

      <div style="background:#f0fdf4;border:1px solid #86efac;border-radius:8px;padding:16px;margin-bottom:24px;">
        <p style="margin:0;font-size:13px;color:#15803d;"><strong>Tip:</strong> Rankings typically update in GSC 3–7 days after Google recrawls a page. Changes made in the last week may not appear yet.</p>
      </div>

    </div>

    <div style="background:#1e293b;border-radius:0 0 12px 12px;padding:16px 28px;text-align:center;">
      <p style="margin:0;color:rgba(255,255,255,0.5);font-size:12px;">BestHospice.com SEO Engine • Sent automatically every Monday & Thursday at 8am</p>
    </div>

  </div>
</body>
</html>`;
}

// ─── Send via SendGrid ────────────────────────────────────────────────────────

function sendEmail(subject, html) {
  return new Promise((resolve, reject) => {
    if (!SENDGRID_API_KEY) {
      reject(new Error('SENDGRID_API_KEY not set in .env'));
      return;
    }

    const body = JSON.stringify({
      personalizations: [{ to: [{ email: TO_EMAIL }] }],
      from: { email: FROM_EMAIL, name: 'BestHospice SEO Engine' },
      subject,
      content: [{ type: 'text/html', value: html }],
    });

    const req = https.request({
      hostname: 'api.sendgrid.com',
      path: '/v3/mail/send',
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${SENDGRID_API_KEY}`,
        'Content-Type': 'application/json',
        'Content-Length': Buffer.byteLength(body),
      },
    }, (res) => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => {
        if (res.statusCode >= 200 && res.statusCode < 300) {
          resolve(res.statusCode);
        } else {
          reject(new Error(`SendGrid error ${res.statusCode}: ${data}`));
        }
      });
    });

    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

// ─── Main ────────────────────────────────────────────────────────────────────

async function main() {
  console.log('📧 BestHospice SEO Email Report starting...');

  const snapshot = await pullGSCSnapshot();
  const prev = loadPreviousReport();

  const dayName = new Date().toLocaleDateString('en-US', { weekday: 'long' });
  const subject = `BestHospice SEO Update — ${dayName} ${new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric' })} | ${snapshot.totals.clicks} clicks, pos ${snapshot.totals.position.toFixed(1)}`;

  const html = buildEmailHtml(snapshot, prev);
  await sendEmail(subject, html);

  console.log(`✅ Report sent to ${TO_EMAIL}`);
  console.log(`   Clicks: ${snapshot.totals.clicks} | Impressions: ${snapshot.totals.impressions} | Avg pos: ${snapshot.totals.position.toFixed(1)}`);
}

main().catch(err => {
  console.error('❌ Email report failed:', err.message);
  process.exit(1);
});
