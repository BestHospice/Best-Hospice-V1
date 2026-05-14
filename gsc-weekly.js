require('dotenv').config({ path: require('os').homedir() + '/.crawford_keys' });
const https = require('https');

const CLIENT_ID = process.env.GSC_CLIENT_ID;
const CLIENT_SECRET = process.env.GSC_CLIENT_SECRET;
const REFRESH_TOKEN = process.env.GSC_REFRESH_TOKEN;
const SITE = 'sc-domain:besthospice.com';

function apiPost(path, token, body) {
  return new Promise((resolve, reject) => {
    const b = JSON.stringify(body);
    const r = https.request({ hostname:'searchconsole.googleapis.com', path, method:'POST', headers:{ Authorization:`Bearer ${token}`, 'Content-Type':'application/json', 'Content-Length':Buffer.byteLength(b) } }, res => { let d=''; res.on('data',c=>d+=c); res.on('end',()=>{ try{resolve(JSON.parse(d))}catch(e){resolve(d)} }); });
    r.on('error', reject); r.write(b); r.end();
  });
}

function addDays(dateStr, n) {
  const d = new Date(dateStr + 'T12:00:00Z');
  d.setUTCDate(d.getUTCDate() + n);
  return d.toISOString().slice(0, 10);
}

function daysAgo(n) {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() - n);
  return d.toISOString().slice(0, 10);
}

(async () => {
  const tRes = await new Promise((resolve, reject) => {
    const b = `client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&refresh_token=${REFRESH_TOKEN}&grant_type=refresh_token`;
    const r = https.request({ hostname:'oauth2.googleapis.com', path:'/token', method:'POST', headers:{'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(b)} }, res => { let d=''; res.on('data',c=>d+=c); res.on('end',()=>resolve(JSON.parse(d))); });
    r.on('error', reject); r.write(b); r.end();
  });
  const token = tRes.access_token;
  const base = `/webmasters/v3/sites/${encodeURIComponent(SITE)}/searchAnalytics/query`;

  // Build 8 weeks ending 3 days ago (GSC lag)
  let weekEnd = daysAgo(3);
  const weeks = [];
  for (let i = 0; i < 8; i++) {
    const weekStart = addDays(weekEnd, -6);
    weeks.unshift({ start: weekStart, end: weekEnd });
    weekEnd = addDays(weekStart, -1);
  }

  console.log('\n=== BEST HOSPICE — WEEK BY WEEK ===');
  console.log('Week                       | Clicks | Impressions | Avg Position');
  console.log('---------------------------|--------|-------------|-------------');

  for (const w of weeks) {
    const res = await apiPost(base, token, {
      startDate: w.start,
      endDate: w.end,
      dimensions: ['date'],
      rowLimit: 7
    });
    const rows = res.rows || [];
    const clicks = rows.reduce((a, r) => a + r.clicks, 0);
    const impressions = rows.reduce((a, r) => a + r.impressions, 0);
    const pos = rows.length ? (rows.reduce((a, r) => a + r.position, 0) / rows.length).toFixed(1) : 'n/a';
    console.log(`${w.start} → ${w.end} |   ${String(clicks).padStart(3)}  |    ${String(impressions).padStart(5)}    |   ${pos}`);
  }
})();
