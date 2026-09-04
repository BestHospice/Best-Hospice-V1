#!/usr/bin/env node
/**
 * Guards the provider-facing analytics promise on provider-billing.html.
 *
 * The billing page is a sales promise: whatever it says the Analytics feature
 * reports, the product must actually report. The earlier copy promised
 * "listing impressions", "admissions", "monthly cost" and "cost per admission".
 * None of those are implemented. Worse, the underlying ProviderImpression rows
 * join to Lead, so they measure referral-match activity against a family
 * request, not a listing or search view — "listing impressions" named the
 * wrong thing entirely.
 *
 * Rather than pattern-matching the prose in isolation, the accuracy assertions
 * tie each metric the page claims back to the shipped provider-visible label in
 * provider-intelligence.html and the field actually returned by
 * provider-funnel.js, so the copy cannot drift away from the product again.
 *
 * Copy-only guard: it asserts pricing and billing prose are untouched, and
 * proves no forbidden metric promise reappears.
 *
 *   node scripts/test-provider-billing-copy.js
 */
const fs = require('fs');
const path = require('path');

const ROOT = path.join(__dirname, '..');
const BILLING = fs.readFileSync(path.join(ROOT, 'provider-billing.html'), 'utf8');
const INTEL = fs.readFileSync(path.join(ROOT, 'provider-intelligence.html'), 'utf8');
const FUNNEL_SRC = fs.readFileSync(path.join(ROOT, 'provider-funnel.js'), 'utf8');

let pass = 0, fail = 0;
const ok = (c, label, detail) => {
  console.log(`  ${c ? 'ok  ' : 'FAIL'} ${label}${c || !detail ? '' : `  — ${detail}`}`);
  c ? pass++ : fail++;
};
const section = (t) => console.log(`\n--- ${t} ---`);

// The Analytics bullet is the sales promise under audit. Isolate it so a
// forbidden word living in unrelated prose cannot mask a regression here, and
// so an assertion cannot accidentally pass by matching another bullet.
const ANALYTICS = (BILLING.match(/<li><strong>Analytics<\/strong>[\s\S]*?<\/li>/) || [''])[0];

// ============ 1. the stale, inaccurate promises are gone ====================
section('1. retired promises absent from the Analytics bullet');

ok(ANALYTICS.length > 0, '1a. the Analytics bullet is still present and parseable');
ok(!/listing impression/i.test(ANALYTICS),
   '1b. no "listing impressions" — the metric is referral-match activity, not a listing view');
ok(!/cost per admission/i.test(ANALYTICS), '1c. no "cost per admission"');
ok(!/monthly cost/i.test(ANALYTICS), '1d. no "monthly cost" analytics promise');
ok(!/\bROI\b/i.test(ANALYTICS), '1e. no ROI claim');

// "impression" in ANY form is the specific inaccuracy that shipped. Guard the
// whole page, not just the bullet, so it cannot reappear elsewhere as a feature.
ok(!/impression/i.test(BILLING), '1f. the word "impression" appears nowhere on the billing page');

// ============ 2. no unimplemented performance promises introduced ===========
section('2. no response-timing / rate / admission-rate promises');

for (const [rx, label] of [
  [/response time/i, 'response time'],
  [/response rate/i, 'response rate'],
  [/admission rate/i, 'admission rate'],
  [/admit rate/i, 'admit rate'],
  [/performance score/i, 'performance score'],
  [/benchmark/i, 'benchmark'],
  [/percentile/i, 'percentile'],
  [/\brank(ing|ed)?\b/i, 'ranking']
]) {
  ok(!rx.test(ANALYTICS), `2. no "${label}" promise in the Analytics bullet`);
}

// "admissions" as a standalone analytics deliverable is not implemented. The
// recorded Admitted *status* is — the copy may only promise the statuses.
ok(!/\badmissions\b/i.test(ANALYTICS),
   '2i. no standalone "admissions" analytics metric');

// ============ 3. the replacement copy matches the shipped product ===========
section('3. replacement copy describes analytics that actually exist');

ok(/referral activity/i.test(ANALYTICS),
   '3a. scoped to the provider\'s own Best Hospice referral activity');

// Each claimed metric must exist as a shipped provider-visible label AND as a
// field the funnel module actually returns.
ok(/families matched/i.test(ANALYTICS) && INTEL.includes("'Families matched'")
   && /timesMatched/.test(FUNNEL_SRC),
   '3b. "families matched" is the shipped label for a real returned field');
ok(/referrals we sent you|referrals sent/i.test(ANALYTICS) && INTEL.includes("'Referrals sent'")
   && /referralsSent/.test(FUNNEL_SRC),
   '3c. "referrals sent" is the shipped label for a real returned field');
ok(/status(es)? your team records/i.test(ANALYTICS) && /sourceStatuses/.test(FUNNEL_SRC),
   '3d. recorded statuses are described as recorded, matching the outcome buckets');

// The CMS market intelligence half of the bullet is implemented and stays.
ok(/public Medicare datasets/i.test(ANALYTICS), '3e. CMS market data claim retained');
ok(/quality measures/i.test(ANALYTICS) && /ownership makeup/i.test(ANALYTICS),
   '3f. CMS quality and ownership claims retained');

// Conservative framing: the page must not imply Best Hospice sees work done
// outside it, which is the limitation provider-funnel.js documents.
ok(!/all your referrals|every referral you receive/i.test(ANALYTICS),
   '3g. no claim to referral activity outside Best Hospice');

// ============ 4. billing behavior and pricing prose untouched ===============
section('4. no billing / pricing change');

ok(/\$250/.test(BILLING), '4a. $250 Partner price intact');
ok(/one Partner subscription/i.test(BILLING), '4b. single-tier statement intact');
ok(/Enterprise pricing/i.test(BILLING), '4c. Enterprise pricing statement intact');
ok(/flat monthly fee/i.test(BILLING), '4d. flat-fee statement intact');
ok(/we take no commission on any admission/i.test(BILLING),
   '4e. no-commission statement intact');
ok(/processed securely by Stripe/i.test(BILLING), '4f. Stripe processing statement intact');
ok(/not a healthcare provider/i.test(BILLING), '4g. non-provider disclaimer intact');
ok(/no paid placement/i.test(BILLING), '4h. no-paid-placement statement intact');

// The three-part structure of what a subscription includes is unchanged.
for (const feature of ['Listing', 'Analytics', 'Support']) {
  ok(new RegExp(`<li><strong>${feature}</strong>`).test(BILLING),
     `4. the "${feature}" bullet is still present`);
}

console.log(`\n${fail ? 'FAILED' : 'PASSED'} — ${pass} passed, ${fail} failed`);
process.exit(fail ? 1 : 0);
