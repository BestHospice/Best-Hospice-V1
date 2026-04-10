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

function daysAgo(n) { const d=new Date(); d.setDate(d.getDate()-n); return d.toISOString().slice(0,10); }

(async () => {
  const tRes = await new Promise((resolve,reject)=>{ const b=`client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&refresh_token=${REFRESH_TOKEN}&grant_type=refresh_token`; const r=https.request({hostname:'oauth2.googleapis.com',path:'/token',method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded','Content-Length':Buffer.byteLength(b)}},res=>{let d='';res.on('data',c=>d+=c);res.on('end',()=>resolve(JSON.parse(d)));});r.on('error',reject);r.write(b);r.end(); });
  const token = tRes.access_token;

  const end = daysAgo(3);
  const start30 = daysAgo(33);
  const startPrev = daysAgo(63);
  const endPrev = daysAgo(34);
  const base = `/webmasters/v3/sites/${encodeURIComponent(SITE)}/searchAnalytics/query`;

  const [cur, prev, byPage, byQuery] = await Promise.all([
    apiPost(base, token, { startDate:start30, endDate:end, dimensions:['date'], rowLimit:100 }),
    apiPost(base, token, { startDate:startPrev, endDate:endPrev, dimensions:['date'], rowLimit:100 }),
    apiPost(base, token, { startDate:start30, endDate:end, dimensions:['page'], rowLimit:20 }),
    apiPost(base, token, { startDate:start30, endDate:end, dimensions:['query'], rowLimit:25 }),
  ]);

  const sum = rows => (rows||[]).reduce((a,r)=>({clicks:a.clicks+r.clicks,impressions:a.impressions+r.impressions}),{clicks:0,impressions:0});
  const pct = (a,b) => b===0?'n/a':((a-b)/b*100).toFixed(1)+'%';

  const c = sum(cur.rows);
  const p = sum(prev.rows);

  console.log('\n=== BEST HOSPICE GSC REPORT ===');
  console.log(`Period: ${start30} → ${end}  vs  ${startPrev} → ${endPrev}\n`);
  console.log(`CLICKS:      ${c.clicks}  (prev: ${p.clicks}, ${pct(c.clicks, p.clicks)})`);
  console.log(`IMPRESSIONS: ${c.impressions}  (prev: ${p.impressions}, ${pct(c.impressions, p.impressions)})\n`);

  console.log('--- TOP PAGES (last 30d) ---');
  (byPage.rows||[]).forEach(r => {
    const page = r.keys[0].replace('https://www.besthospice.com','');
    console.log(`  ${r.clicks} clicks | ${r.impressions} imp | pos ${Number(r.position).toFixed(1)} | ${page}`);
  });

  console.log('\n--- TOP QUERIES (last 30d) ---');
  (byQuery.rows||[]).forEach(r => {
    console.log(`  ${r.clicks} clicks | ${r.impressions} imp | pos ${Number(r.position).toFixed(1)} | "${r.keys[0]}"`);
  });

  const opps = (byQuery.rows||[]).filter(r=>r.impressions>=5&&r.clicks===0).sort((a,b)=>b.impressions-a.impressions).slice(0,10);
  if (opps.length) {
    console.log('\n--- OPPORTUNITIES (impressions, 0 clicks) ---');
    opps.forEach(r=>console.log(`  ${r.impressions} imp | pos ${Number(r.position).toFixed(1)} | "${r.keys[0]}"`));
  }
})();
