'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { XMLParser } = require('fast-xml-parser');
const Anthropic = require('@anthropic-ai/sdk');
const sgMail = require('@sendgrid/mail');

const SCHEDULE_PATH = path.join(__dirname, 'newsletter', 'schedule.json');
const NEWSLETTER_DIR = path.join(__dirname, 'newsletter');
const LOGS_DIR = path.join(__dirname, 'logs');
const LOG_PATH = path.join(LOGS_DIR, 'newsletter-pipeline.log');
const CANONICAL_DOMAIN = process.env.CANONICAL_DOMAIN || 'https://www.besthospice.com';

const RSS_FEEDS = [
  { name: 'CMS.gov', url: 'https://www.cms.gov/newsroom/rss/all' },
  { name: 'AARP', url: 'https://www.aarp.org/rss/news/' },
  { name: 'National Institute on Aging', url: 'https://www.nia.nih.gov/news/rss.xml' },
  { name: 'Kaiser Family Foundation', url: 'https://kff.org/feed/' },
  { name: 'LeadingAge', url: 'https://leadingage.org/feed/' },
];

// ---------------------------------------------------------------------------
// Logging
// ---------------------------------------------------------------------------

function pipelineLog(action, status, detail) {
  const ts = new Date().toISOString().replace('T', ' ').slice(0, 16);
  const line = `[${ts}] PIPELINE: newsletter | ACTION: ${action} | STATUS: ${status} | DETAIL: ${detail}\n`;
  try {
    if (!fs.existsSync(LOGS_DIR)) fs.mkdirSync(LOGS_DIR, { recursive: true });
    fs.appendFileSync(LOG_PATH, line);
  } catch (e) {
    console.error('Log write failed:', e.message);
  }
  console.log(line.trim());
}

// ---------------------------------------------------------------------------
// Schedule helpers
// ---------------------------------------------------------------------------

function loadSchedule() {
  try {
    if (fs.existsSync(SCHEDULE_PATH)) {
      return JSON.parse(fs.readFileSync(SCHEDULE_PATH, 'utf8'));
    }
  } catch (e) {
    console.error('schedule.json read failed:', e.message);
  }
  return { last_sent: null, last_issue: 0, issues: [] };
}

function saveSchedule(data) {
  if (!fs.existsSync(NEWSLETTER_DIR)) fs.mkdirSync(NEWSLETTER_DIR, { recursive: true });
  fs.writeFileSync(SCHEDULE_PATH, JSON.stringify(data, null, 2));
}

function shouldRunToday() {
  const schedule = loadSchedule();
  if (!schedule.last_sent) return true;
  const daysDiff = (Date.now() - new Date(schedule.last_sent).getTime()) / (1000 * 60 * 60 * 24);
  return daysDiff >= 14;
}

// ---------------------------------------------------------------------------
// RSS fetching
// ---------------------------------------------------------------------------

function fetchUrl(url, redirectDepth = 0) {
  if (redirectDepth > 4) return Promise.reject(new Error('Too many redirects'));
  return new Promise((resolve, reject) => {
    const mod = url.startsWith('https') ? https : http;
    const req = mod.get(url, { headers: { 'User-Agent': 'BestHospice-Newsletter/1.0' }, timeout: 12000 }, (res) => {
      if (res.statusCode >= 300 && res.statusCode < 400 && res.headers.location) {
        return resolve(fetchUrl(res.headers.location, redirectDepth + 1));
      }
      let data = '';
      res.on('data', (chunk) => { data += chunk; });
      res.on('end', () => resolve(data));
    });
    req.on('error', reject);
    req.on('timeout', () => { req.destroy(); reject(new Error('Request timeout')); });
  });
}

function parseItems(parsed) {
  // RSS 2.0
  const rssItems = parsed?.rss?.channel?.item;
  if (rssItems) {
    const arr = Array.isArray(rssItems) ? rssItems : [rssItems];
    return arr.map((i) => ({
      title: String(i.title || '').trim(),
      link: String(i.link || '').trim(),
      pubDate: i.pubDate || i['dc:date'] || '',
      description: String(i.description || i.summary || '')
        .replace(/<[^>]+>/g, '').trim().slice(0, 280),
    }));
  }
  // Atom
  const atomEntries = parsed?.feed?.entry;
  if (atomEntries) {
    const arr = Array.isArray(atomEntries) ? atomEntries : [atomEntries];
    return arr.map((i) => {
      const linkHref = Array.isArray(i.link)
        ? (i.link.find((l) => l['@_rel'] !== 'alternate' || !l['@_rel'])?.['@_href'] || i.link[0]?.['@_href'] || '')
        : (i.link?.['@_href'] || String(i.link || ''));
      return {
        title: String(i.title?.['#text'] || i.title || '').trim(),
        link: String(linkHref).trim(),
        pubDate: i.published || i.updated || '',
        description: String(i.summary?.['#text'] || i.summary || i.content?.['#text'] || i.content || '')
          .replace(/<[^>]+>/g, '').trim().slice(0, 280),
      };
    });
  }
  return [];
}

async function fetchFeed(feed) {
  const xml = await fetchUrl(feed.url);
  const parser = new XMLParser({ ignoreAttributes: false, attributeNamePrefix: '@_' });
  const parsed = parser.parse(xml);
  const items = parseItems(parsed);
  const thirtyDaysAgo = Date.now() - 30 * 24 * 60 * 60 * 1000;
  return items
    .filter((i) => {
      if (!i.pubDate) return true;
      const d = new Date(i.pubDate);
      return Number.isNaN(d.getTime()) || d.getTime() > thirtyDaysAgo;
    })
    .slice(0, 5);
}

async function fetchAllFeeds() {
  const all = [];
  for (const feed of RSS_FEEDS) {
    try {
      const items = await fetchFeed(feed);
      pipelineLog('fetch_feed', 'success', `${feed.name}: ${items.length} items`);
      all.push(...items);
    } catch (err) {
      pipelineLog('fetch_feed', 'failed', `${feed.name}: ${err.message}`);
    }
  }
  // Deduplicate by title prefix
  const seen = new Set();
  const deduped = all.filter((item) => {
    const key = item.title.toLowerCase().slice(0, 55);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
  return deduped.slice(0, 12);
}

// ---------------------------------------------------------------------------
// Unsubscribe tokens (HMAC-SHA256 of email, stateless)
// ---------------------------------------------------------------------------

function generateUnsubscribeToken(email) {
  const secret = process.env.NEWSLETTER_UNSUBSCRIBE_SECRET || 'dev-unsub-secret';
  return crypto.createHmac('sha256', secret).update(email.toLowerCase().trim()).digest('hex');
}

function verifyUnsubscribeToken(email, token) {
  try {
    const expected = generateUnsubscribeToken(email);
    if (token.length !== expected.length) return false;
    return crypto.timingSafeEqual(Buffer.from(token, 'hex'), Buffer.from(expected, 'hex'));
  } catch (_) {
    return false;
  }
}

// ---------------------------------------------------------------------------
// Claude content generation
// ---------------------------------------------------------------------------

function formatNewsItems(items) {
  return items
    .map((item, i) => {
      const desc = item.description ? `\n   ${item.description}` : '';
      return `${i + 1}. ${item.title}${desc}`;
    })
    .join('\n\n');
}

async function generateContent(articles, issueNumber) {
  const anthropic = new Anthropic();
  const date = new Date().toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });

  const systemPrompt = `You are a newsletter writer for Best Hospice and Home Health, a free service that connects families with verified hospice and home care providers across the United States. You write a biweekly newsletter called "The Best Hospice and Home Health Brief" that goes out to families navigating elder care decisions.

Your writing style is warm, clear, and direct. You write like a knowledgeable friend who happens to understand healthcare, not like a corporate publication. Use plain language. Write in full sentences and paragraphs. Do not use bullet point lists or numbered lists. Do not use dashes of any kind, including em dashes and en dashes. Instead of dashes, use commas, semicolons, or restructure the sentence entirely. Avoid words and phrases that signal AI writing: do not use "delve", "navigate", "landscape", "it's worth noting", "importantly", "in conclusion", "in summary", "furthermore", or "moreover". Vary your sentence length naturally. Occasionally use a short, punchy sentence for emphasis.

Every issue has four sections. Write all four.`;

  const userPrompt = `Today is ${date}. Here are recent news items and developments in elder care and hospice. Please write Issue #${issueNumber} of The Best Hospice and Home Health Brief newsletter.

NEWS ITEMS:
${formatNewsItems(articles)}

Write the newsletter with these four sections:

1. WHAT'S HAPPENING — A 2 to 3 paragraph overview of the most important recent developments in elder care, hospice policy, or Medicare. Make it feel like you're catching up a friend, not writing a report.

2. WHAT TO WATCH FOR — A 1 to 2 paragraph section on something families should be paying attention to right now. This could be a regulatory change, a coverage shift, a seasonal pattern, or a common pitfall. Be specific and practical.

3. MONEY AND BENEFITS — A 1 to 2 paragraph breakdown of something financial: Medicare coverage nuances, what hospice actually costs families, benefit changes, or how to avoid common billing surprises. Be concrete with numbers when you have them.

4. FROM THE TEAM — A short closing paragraph (3 to 5 sentences) from the Best Hospice and Home Health team. Warm and human. Remind readers that Best Hospice is free for families, and encourage them to share with anyone who might need help finding care.

Format your response as JSON with this shape:
{
  "subject": "email subject line (under 60 characters, no dashes)",
  "preview": "email preview text (under 90 characters)",
  "whatsHappening": { "heading": "...", "body": "..." },
  "watchFor": { "heading": "...", "body": "..." },
  "moneyAndBenefits": { "heading": "...", "body": "..." },
  "fromTheTeam": { "heading": "...", "body": "..." }
}`;

  const response = await anthropic.messages.create({
    model: 'claude-opus-4-6',
    max_tokens: 2400,
    system: systemPrompt,
    messages: [{ role: 'user', content: userPrompt }],
  });

  const text = response.content[0]?.text || '';
  const jsonMatch = text.match(/\{[\s\S]*\}/);
  if (!jsonMatch) throw new Error('No JSON object found in Claude response');

  const content = JSON.parse(jsonMatch[0]);

  const required = ['subject', 'preview', 'whatsHappening', 'watchFor', 'moneyAndBenefits', 'fromTheTeam'];
  for (const field of required) {
    if (!content[field]) throw new Error(`Missing required field in Claude response: ${field}`);
  }

  // Validate no dashes
  const allText = JSON.stringify(content);
  if (/[–—]/.test(allText) || / - /.test(allText)) {
    pipelineLog('content_check', 'warning', 'Dashes detected in generated content');
  }

  return content;
}

// ---------------------------------------------------------------------------
// Email HTML builder (inline styles, table layout)
// ---------------------------------------------------------------------------

function buildEmailSection(s) {
  const bodyHtml = String(s.body || '').replace(/\n\n/g, '</p><p style="margin:12px 0 0;font-size:15px;line-height:1.75;color:#0b1220;font-family:-apple-system,BlinkMacSystemFont,\'Segoe UI\',sans-serif;">').replace(/\n/g, '<br>');
  return `
    <tr><td style="padding:0 0 14px 0;">
      <table width="100%" cellpadding="0" cellspacing="0" border="0"
        style="background:#ffffff;border-radius:8px;border-top:3px solid #e2e8f0;border:1px solid #e2e8f0;">
        <tr><td style="padding:20px 24px;">
          <h2 style="margin:0 0 10px;font-size:15px;font-weight:700;color:#0f766e;
            font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;letter-spacing:-0.01em;">${s.heading}</h2>
          <p style="margin:0;font-size:15px;line-height:1.75;color:#0b1220;
            font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">${bodyHtml}</p>
        </td></tr>
      </table>
    </td></tr>`;
}

function buildEmailHtml(content, issueNumber, sendDate, subscriberEmail) {
  const token = generateUnsubscribeToken(subscriberEmail);
  const unsubUrl = `${CANONICAL_DOMAIN}/newsletter/unsubscribe?email=${encodeURIComponent(subscriberEmail)}&token=${encodeURIComponent(token)}`;
  const monthName = sendDate.toLocaleString('en-US', { month: 'long' }).toLowerCase();
  const webUrl = `${CANONICAL_DOMAIN}/newsletter/issue-${issueNumber}-${monthName}-${sendDate.getFullYear()}`;
  const formattedDate = sendDate.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>${content.subject}</title>
</head>
<body style="margin:0;padding:0;background:#f6f7fb;">
<table width="100%" cellpadding="0" cellspacing="0" border="0" style="background:#f6f7fb;">
  <tr><td align="center" style="padding:24px 16px;">
    <table width="600" cellpadding="0" cellspacing="0" border="0" style="max-width:600px;width:100%;">
      <tr><td style="background:linear-gradient(135deg,#0f766e,#0b4f6c);border-radius:12px 12px 0 0;padding:28px 32px 24px;">
        <p style="margin:0 0 6px;font-size:11px;font-weight:600;letter-spacing:0.09em;color:rgba(255,255,255,0.72);
          text-transform:uppercase;font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
          Issue #${issueNumber} &middot; ${formattedDate}</p>
        <h1 style="margin:0 0 8px;font-size:26px;font-weight:700;color:#ffffff;letter-spacing:-0.02em;
          font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">The Best Hospice and Home Health Brief</h1>
        <p style="margin:0;font-size:14px;color:rgba(255,255,255,0.82);
          font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">${content.preview}</p>
      </td></tr>
      <tr><td style="background:#f6f7fb;padding:16px 0 4px;">
        <table width="100%" cellpadding="0" cellspacing="0" border="0">
          ${buildEmailSection(content.whatsHappening)}
          ${buildEmailSection(content.watchFor)}
          ${buildEmailSection(content.moneyAndBenefits)}
          ${buildEmailSection(content.fromTheTeam)}
          <tr><td style="padding:10px 0 20px;text-align:center;">
            <a href="${CANONICAL_DOMAIN}"
              style="display:inline-block;background:linear-gradient(135deg,#0f766e,#0b4f6c);
                color:#ffffff;font-weight:700;font-size:15px;text-decoration:none;
                padding:14px 30px;border-radius:8px;
                font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
              Find Hospice Providers Near You
            </a>
          </td></tr>
        </table>
      </td></tr>
      <tr><td style="background:#f1f5f9;border-radius:0 0 12px 12px;padding:18px 32px;text-align:center;">
        <p style="margin:0 0 6px;font-size:12px;color:#5b6474;
          font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
          <a href="${webUrl}" style="color:#0f766e;text-decoration:none;">View this issue on the web</a>
        </p>
        <p style="margin:0 0 6px;font-size:12px;color:#5b6474;
          font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
          Best Hospice and Home Health &middot; United States &middot; contact@besthospice.com
        </p>
        <p style="margin:0;font-size:12px;color:#5b6474;
          font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',sans-serif;">
          <a href="${unsubUrl}" style="color:#5b6474;text-decoration:underline;">Unsubscribe</a>
        </p>
      </td></tr>
    </table>
  </td></tr>
</table>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Web archive HTML builder
// ---------------------------------------------------------------------------

function buildWebSection(s) {
  const paras = String(s.body || '').split('\n\n').filter(Boolean);
  const parasHtml = paras
    .map((p) => `<p style="margin:0 0 14px;line-height:1.8;">${p.replace(/\n/g, '<br>')}</p>`)
    .join('');
  return `
  <div class="card" style="padding:24px;margin-bottom:16px;">
    <h2 style="margin:0 0 14px;color:#0f766e;">${s.heading}</h2>
    ${parasHtml}
  </div>`;
}

function buildWebHtml(content, issueNumber, slug, sendDate) {
  const formattedDate = sendDate.toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' });
  const schemaDate = sendDate.toISOString().slice(0, 10);

  const schema = JSON.stringify({
    '@context': 'https://schema.org',
    '@type': 'Article',
    headline: content.subject,
    description: content.preview,
    datePublished: schemaDate,
    publisher: {
      '@type': 'Organization',
      name: 'Best Hospice and Home Health',
      url: CANONICAL_DOMAIN,
    },
  });

  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>${content.subject} | The Best Hospice and Home Health Brief Issue #${issueNumber}</title>
  <meta name="description" content="${content.preview}">
  <link rel="canonical" href="${CANONICAL_DOMAIN}/newsletter/${slug}">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Sora:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/styles-modern.css">
  <link rel="stylesheet" href="/styles/main.css">
  <script type="application/ld+json">${schema}</script>
</head>
<body>
  <div style="max-width:700px;margin:0 auto;padding:24px 16px;">
    <p style="margin:0 0 20px;">
      <a href="/newsletter" style="color:#0f766e;text-decoration:none;font-size:14px;">&larr; Back to all issues</a>
    </p>
    <div style="background:linear-gradient(135deg,#0f766e,#0b4f6c);border-radius:14px;padding:28px 32px;margin-bottom:16px;">
      <p style="margin:0 0 6px;font-size:12px;font-weight:600;letter-spacing:0.07em;
        color:rgba(255,255,255,0.72);text-transform:uppercase;">
        Issue #${issueNumber} &middot; ${formattedDate}
      </p>
      <h1 style="margin:0 0 8px;color:#fff;font-size:clamp(1.3rem,3vw,1.9rem);letter-spacing:-0.02em;">${content.subject}</h1>
      <p style="margin:0;color:rgba(255,255,255,0.84);font-size:15px;">${content.preview}</p>
    </div>
    ${buildWebSection(content.whatsHappening)}
    ${buildWebSection(content.watchFor)}
    ${buildWebSection(content.moneyAndBenefits)}
    ${buildWebSection(content.fromTheTeam)}
    <div style="margin:24px 0;text-align:center;">
      <a class="button" href="${CANONICAL_DOMAIN}" style="text-decoration:none;">Find Care Near You</a>
    </div>
    <p style="text-align:center;margin-bottom:0;">
      <a href="/newsletter" style="color:#0f766e;text-decoration:none;font-size:14px;">&larr; Back to all issues</a>
    </p>
    <footer class="site-footer" style="margin-top:32px;">
      <div class="footer-inner">
        <div class="footer-brand">Best Hospice and Home Health</div>
        <div class="footer-meta">Contact: contact@besthospice.com &middot; United States</div>
        <div class="footer-links">
          <a href="/privacy.html">Privacy Policy</a>
          <a href="/cookie-policy.html">Cookie Policy</a>
          <a href="/terms.html">Terms of Service</a>
        </div>
      </div>
    </footer>
  </div>
</body>
</html>`;
}

// ---------------------------------------------------------------------------
// Archive index regeneration
// ---------------------------------------------------------------------------

function regenerateIndex(schedule) {
  const issues = (schedule.issues || []).slice().sort((a, b) => b.issue - a.issue);
  const cards = issues
    .map((iss) => {
      const dateStr = iss.date
        ? new Date(iss.date + 'T12:00:00').toLocaleDateString('en-US', { month: 'long', day: 'numeric', year: 'numeric' })
        : '';
      return `
    <div class="card" style="padding:20px;margin-bottom:16px;">
      <p style="margin:0 0 4px;font-size:13px;color:#5b6474;">Issue #${iss.issue} &middot; ${dateStr}</p>
      <h2 style="margin:0 0 8px;font-size:1.1rem;">${iss.subject}</h2>
      <p style="margin:0 0 14px;color:#5b6474;font-size:14px;">${iss.preview}</p>
      <a class="button" href="/newsletter/${iss.slug}" style="text-decoration:none;font-size:14px;padding:10px 16px;">Read this issue</a>
    </div>`;
    })
    .join('');

  const html = `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>The Best Hospice and Home Health Brief | Newsletter Archive</title>
  <meta name="description" content="Past issues of The Best Hospice and Home Health Brief, a biweekly newsletter from Best Hospice and Home Health covering elder care, hospice policy, Medicare, and family guidance.">
  <link rel="canonical" href="${CANONICAL_DOMAIN}/newsletter">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Sora:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <link rel="stylesheet" href="/styles-modern.css">
  <link rel="stylesheet" href="/styles/main.css">
</head>
<body>
  <div style="max-width:700px;margin:0 auto;padding:24px 16px;">
    <p style="margin:0 0 20px;">
      <a href="/" style="color:#0f766e;text-decoration:none;font-size:14px;">&larr; Back to BestHospice.com</a>
    </p>
    <h1 style="margin:0 0 6px;">The Best Hospice and Home Health Brief</h1>
    <p style="margin:0 0 28px;color:#5b6474;">A biweekly newsletter for families navigating elder care. Practical, clear, and free.</p>
    ${issues.length ? cards : '<p style="color:#5b6474;">No issues yet. Check back soon.</p>'}
    <footer class="site-footer" style="margin-top:32px;">
      <div class="footer-inner">
        <div class="footer-brand">Best Hospice and Home Health</div>
        <div class="footer-meta">Contact: contact@besthospice.com &middot; United States</div>
        <div class="footer-links">
          <a href="/privacy.html">Privacy Policy</a>
          <a href="/cookie-policy.html">Cookie Policy</a>
          <a href="/terms.html">Terms of Service</a>
        </div>
      </div>
    </footer>
  </div>
</body>
</html>`;

  if (!fs.existsSync(NEWSLETTER_DIR)) fs.mkdirSync(NEWSLETTER_DIR, { recursive: true });
  fs.writeFileSync(path.join(NEWSLETTER_DIR, 'index.html'), html);
}

// ---------------------------------------------------------------------------
// Main pipeline
// ---------------------------------------------------------------------------

async function runNewsletterPipeline(prisma, { force = false } = {}) {
  pipelineLog('pipeline', 'start', force ? 'manual trigger' : 'scheduled run');

  if (!force && !shouldRunToday()) {
    pipelineLog('pipeline', 'skipped', 'Fewer than 14 days since last send');
    return { skipped: true };
  }

  const schedule = loadSchedule();
  const issueNumber = (schedule.last_issue || 0) + 1;
  const sendDate = new Date();
  const monthName = sendDate.toLocaleString('en-US', { month: 'long' }).toLowerCase();
  const slug = `issue-${issueNumber}-${monthName}-${sendDate.getFullYear()}`;

  // Step 1: Fetch RSS feeds
  pipelineLog('fetch_feeds', 'start', `Fetching ${RSS_FEEDS.length} feeds`);
  let articles = [];
  try {
    articles = await fetchAllFeeds();
    if (articles.length < 3) {
      pipelineLog('fetch_feeds', 'warning', `Only ${articles.length} articles found; proceeding anyway`);
    } else {
      pipelineLog('fetch_feeds', 'success', `${articles.length} articles collected`);
    }
  } catch (err) {
    pipelineLog('fetch_feeds', 'failed', err.message);
    throw err;
  }

  // Step 2: Generate content with Claude
  pipelineLog('generate', 'start', `Generating Issue #${issueNumber}`);
  let content;
  try {
    content = await generateContent(articles, issueNumber);
    pipelineLog('generate', 'success', `Subject: ${content.subject}`);
  } catch (err) {
    pipelineLog('generate', 'failed', err.message);
    throw err;
  }

  // Step 3: Fetch subscribers
  pipelineLog('fetch_subscribers', 'start', 'Loading subscribers');
  let subscribers = [];
  try {
    subscribers = await prisma.$queryRawUnsafe(
      `SELECT id, name, email FROM newsletter_subscribers ORDER BY created_at ASC`
    );
    pipelineLog('fetch_subscribers', 'success', `${subscribers.length} subscribers`);
  } catch (err) {
    pipelineLog('fetch_subscribers', 'failed', err.message);
    throw err;
  }

  // Step 4: Send via SendGrid
  let sent = 0;
  let failed = 0;
  if (!process.env.SENDGRID_API_KEY) {
    pipelineLog('send', 'skipped', 'SENDGRID_API_KEY not set; email send skipped');
  } else {
    sgMail.setApiKey(process.env.SENDGRID_API_KEY);
    const fromEmail = process.env.NEWSLETTER_FROM_EMAIL || 'no-reply@besthospice.com';
    pipelineLog('send', 'start', `Sending to ${subscribers.length} subscribers`);
    for (const sub of subscribers) {
      try {
        const html = buildEmailHtml(content, issueNumber, sendDate, sub.email);
        await sgMail.send({
          to: sub.email,
          from: { email: fromEmail, name: 'Best Hospice and Home Health Brief' },
          replyTo: 'contact@besthospice.com',
          subject: content.subject,
          html,
        });
        sent++;
        await new Promise((r) => setTimeout(r, 100));
      } catch (err) {
        failed++;
        pipelineLog('send_email', 'failed', `${sub.email}: ${err.message}`);
      }
    }
    pipelineLog('send', 'success', `Sent: ${sent}, Failed: ${failed}`);
  }

  // Step 5: Save web archive
  pipelineLog('save_archive', 'start', `Saving newsletter/${slug}.html`);
  try {
    if (!fs.existsSync(NEWSLETTER_DIR)) fs.mkdirSync(NEWSLETTER_DIR, { recursive: true });
    const webHtml = buildWebHtml(content, issueNumber, slug, sendDate);
    fs.writeFileSync(path.join(NEWSLETTER_DIR, `${slug}.html`), webHtml);
    pipelineLog('save_archive', 'success', `${slug}.html saved`);
  } catch (err) {
    pipelineLog('save_archive', 'failed', err.message);
  }

  // Step 6: Update schedule.json and regenerate index
  schedule.last_sent = sendDate.toISOString().slice(0, 10);
  schedule.last_issue = issueNumber;
  if (!Array.isArray(schedule.issues)) schedule.issues = [];
  schedule.issues.unshift({
    issue: issueNumber,
    slug,
    subject: content.subject,
    preview: content.preview,
    date: schedule.last_sent,
  });
  saveSchedule(schedule);
  regenerateIndex(schedule);
  pipelineLog('index', 'success', 'newsletter/index.html regenerated');

  pipelineLog('pipeline', 'success', `Issue #${issueNumber} complete. Sent: ${sent}, Failed: ${failed}`);
  return { issueNumber, slug, subject: content.subject, subscriberCount: subscribers.length, sent, failed };
}

module.exports = { runNewsletterPipeline, generateUnsubscribeToken, verifyUnsubscribeToken, shouldRunToday };
