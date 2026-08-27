#!/usr/bin/env node
/**
 * Archive one quarterly CMS hospice release.
 *
 * CMS overwrites its Provider Data Catalog files in place, so any measure that
 * compares releases can only ever use history we kept at the time. This is the
 * cheapest possible insurance: it costs ~5.5 MB per quarter and cannot be
 * reconstructed later.
 *
 * Read-only with respect to CMS and to the site. Writes one directory per
 * release and refuses to overwrite an existing one.
 *
 *   node scripts/cms-archive.js            archive the current release
 *   node scripts/cms-archive.js --list     show what has been archived
 *   node scripts/cms-archive.js --dry-run  resolve and report, download nothing
 */
const fs = require('fs');
const path = require('path');
const zlib = require('zlib');
const crypto = require('crypto');
const https = require('https');

const ROOT = path.join(__dirname, '..');
const ARCHIVE = path.join(ROOT, 'reports', 'cms-archive');
const CATALOG = 'https://data.cms.gov/provider-data/api/1/metastore/schemas/dataset/items?show-reference-ids=false';

// Dataset identifiers, not file names. CMS renames the files every quarter
// (Hospice_Provider_May2026.csv and so on), so the download URL is resolved
// from the catalog each run rather than hardcoded.
const DATASETS = {
  general: 'yc9t-dgbk',
  provider: '252m-zfp9',
  zip: '95rg-2usp',
  cahps_provider: 'gxki-hrr8',
  state: 'eda0-92f0',
  national: '3xeb-u9wp'
};

const get = (url) => new Promise((resolve, reject) => {
  https.get(url, { headers: { 'User-Agent': 'BestHospice-archive/1.0' } }, (res) => {
    if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
      res.resume();
      return get(res.headers.location).then(resolve, reject);
    }
    if (res.statusCode !== 200) { res.resume(); return reject(new Error(`HTTP ${res.statusCode} for ${url}`)); }
    const chunks = [];
    res.on('data', (c) => chunks.push(c));
    res.on('end', () => resolve(Buffer.concat(chunks)));
  }).on('error', reject);
});

const sha256 = (buf) => crypto.createHash('sha256').update(buf).digest('hex');

async function resolve() {
  const items = JSON.parse((await get(CATALOG)).toString('utf8'));
  const byId = new Map(items.map((i) => [i.identifier, i]));
  const out = {};
  for (const [name, id] of Object.entries(DATASETS)) {
    const item = byId.get(id);
    if (!item) throw new Error(`dataset ${id} (${name}) is no longer in the CMS catalog`);
    const dist = (item.distribution || [])[0] || {};
    const url = (dist.data && dist.data.downloadURL) || dist.downloadURL;
    if (!url) throw new Error(`dataset ${id} (${name}) has no download URL`);
    out[name] = { id, title: item.title, modified: item.modified, url };
  }
  return out;
}

// The release is keyed by the newest modified date across the six datasets.
const releaseKey = (r) => Object.values(r).map((d) => d.modified).filter(Boolean).sort().pop();

function list() {
  if (!fs.existsSync(ARCHIVE)) return console.log('no archives yet');
  const dirs = fs.readdirSync(ARCHIVE).filter((d) => fs.statSync(path.join(ARCHIVE, d)).isDirectory()).sort();
  if (!dirs.length) return console.log('no archives yet');
  console.log(`${dirs.length} archived release(s):`);
  for (const d of dirs) {
    const mf = path.join(ARCHIVE, d, 'manifest.json');
    let note = '';
    if (fs.existsSync(mf)) {
      const m = JSON.parse(fs.readFileSync(mf, 'utf8'));
      const mb = Object.values(m.files).reduce((a, f) => a + f.gzipBytes, 0) / 1048576;
      note = `  ${Object.keys(m.files).length} datasets, ${mb.toFixed(1)} MB gz, captured ${m.capturedAt.slice(0, 10)}`;
    }
    console.log(`  ${d}${note}`);
  }
}

async function main() {
  const args = process.argv.slice(2);
  if (args.includes('--list')) return list();

  console.log('resolving current CMS release from the Provider Data Catalog...');
  const resolved = await resolve();
  const key = releaseKey(resolved);
  console.log(`  release key: ${key}`);
  for (const [n, d] of Object.entries(resolved)) console.log(`  ${n.padEnd(16)} modified ${d.modified}`);

  const dir = path.join(ARCHIVE, key);
  if (fs.existsSync(dir)) {
    console.log(`\nrelease ${key} is already archived at ${path.relative(ROOT, dir)} — nothing to do.`);
    console.log('CMS has not published a new release since the last run.');
    return;
  }
  if (args.includes('--dry-run')) {
    console.log(`\n--dry-run: would create ${path.relative(ROOT, dir)} and download 6 datasets.`);
    return;
  }

  fs.mkdirSync(dir, { recursive: true });
  const files = {};
  let totalGz = 0;
  for (const [name, d] of Object.entries(resolved)) {
    process.stdout.write(`  downloading ${name}... `);
    const raw = await get(d.url);
    const gz = zlib.gzipSync(raw, { level: 9 });
    fs.writeFileSync(path.join(dir, `${name}.csv.gz`), gz);
    files[name] = {
      datasetId: d.id, title: d.title, modified: d.modified, sourceUrl: d.url,
      rawBytes: raw.length, gzipBytes: gz.length, sha256Raw: sha256(raw)
    };
    totalGz += gz.length;
    console.log(`${(raw.length / 1048576).toFixed(1)} MB -> ${(gz.length / 1048576).toFixed(2)} MB gz`);
  }

  fs.writeFileSync(path.join(dir, 'manifest.json'), JSON.stringify({
    releaseKey: key,
    capturedAt: new Date().toISOString(),
    catalog: CATALOG,
    note: 'CMS overwrites these files in place. This snapshot is the only record of this release.',
    files
  }, null, 2));

  console.log(`\narchived release ${key} -> ${path.relative(ROOT, dir)} (${(totalGz / 1048576).toFixed(1)} MB total)`);

  // reports/ is gitignored and this machine is the only copy. Say so plainly
  // rather than letting an archive quietly exist in one place.
  const remote = process.env.CMS_ARCHIVE_REMOTE;
  if (remote) {
    console.log(`\nCMS_ARCHIVE_REMOTE is set to ${remote}`);
    console.log('Upload with whichever client is installed, e.g.:');
    console.log(`  rclone copy ${path.relative(ROOT, dir)} ${remote}/${key}`);
    console.log(`  aws s3 cp --recursive ${path.relative(ROOT, dir)} ${remote}/${key} --endpoint-url $CMS_ARCHIVE_ENDPOINT`);
  } else {
    console.log('\nWARNING: this archive exists only on this machine, and reports/ is gitignored.');
    console.log('Set CMS_ARCHIVE_REMOTE (and install rclone or the aws CLI) to get an off-machine copy,');
    console.log('or copy the directory somewhere backed up. The whole point is multi-year history.');
  }
}

main().catch((e) => { console.error('archive failed:', e.message); process.exit(1); });
