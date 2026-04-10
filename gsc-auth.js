/**
 * One-time GSC OAuth setup.
 * Run: node gsc-auth.js
 * Opens auth URL in terminal → open in browser → authorizes → saves GSC_REFRESH_TOKEN to ~/.crawford_keys
 */
require('dotenv').config({ path: require('os').homedir() + '/.crawford_keys' });
const http = require('http');
const https = require('https');
const fs = require('fs');
const os = require('os');

const CLIENT_ID = process.env.GSC_CLIENT_ID;
const CLIENT_SECRET = process.env.GSC_CLIENT_SECRET;
const REDIRECT_URI = 'http://localhost:8585/oauth2callback';
const SCOPE = 'https://www.googleapis.com/auth/webmasters.readonly';
const KEYS_FILE = os.homedir() + '/.crawford_keys';

const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?client_id=${CLIENT_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&response_type=code&scope=${encodeURIComponent(SCOPE)}&access_type=offline&prompt=consent`;

console.log('\n=== GSC OAuth Setup ===');
console.log('\nOpen this URL in your browser:\n');
console.log(authUrl);
console.log('\nWaiting for callback on http://localhost:8585 ...\n');

function exchangeCode(code) {
  return new Promise((resolve, reject) => {
    const body = `code=${encodeURIComponent(code)}&client_id=${CLIENT_ID}&client_secret=${CLIENT_SECRET}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&grant_type=authorization_code`;
    const req = https.request({
      hostname: 'oauth2.googleapis.com',
      path: '/token',
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded', 'Content-Length': Buffer.byteLength(body) }
    }, (res) => {
      let raw = '';
      res.on('data', d => raw += d);
      res.on('end', () => resolve(JSON.parse(raw)));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost:8585');
  if (url.pathname !== '/oauth2callback') {
    res.end('Not found');
    return;
  }

  const code = url.searchParams.get('code');
  const error = url.searchParams.get('error');

  if (error) {
    res.end(`<h2>Error: ${error}</h2>`);
    server.close();
    return;
  }

  if (!code) {
    res.end('<h2>No code received.</h2>');
    server.close();
    return;
  }

  try {
    const tokens = await exchangeCode(code);

    if (!tokens.refresh_token) {
      res.end('<h2>No refresh token returned. Try revoking access at myaccount.google.com/permissions and re-running.</h2>');
      console.error('No refresh_token in response:', tokens);
      server.close();
      return;
    }

    // Append GSC_REFRESH_TOKEN to ~/.crawford_keys
    const existing = fs.readFileSync(KEYS_FILE, 'utf8');
    if (existing.includes('GSC_REFRESH_TOKEN=')) {
      // Replace existing
      const updated = existing.replace(/GSC_REFRESH_TOKEN=.*/g, `GSC_REFRESH_TOKEN=${tokens.refresh_token}`);
      fs.writeFileSync(KEYS_FILE, updated);
    } else {
      fs.appendFileSync(KEYS_FILE, `\n# --- Google Search Console ---\nGSC_REFRESH_TOKEN=${tokens.refresh_token}\n`);
    }

    console.log('\nSuccess! GSC_REFRESH_TOKEN saved to ~/.crawford_keys');
    console.log('You can now close this terminal tab and run: node gsc-report.js\n');

    res.end('<h2>Success! GSC authorized. You can close this tab.</h2><p>GSC_REFRESH_TOKEN has been saved. Run gsc-report.js to pull data.</p>');
    server.close();
  } catch (err) {
    console.error('Token exchange failed:', err);
    res.end(`<h2>Error: ${err.message}</h2>`);
    server.close();
  }
});

server.listen(8585);
