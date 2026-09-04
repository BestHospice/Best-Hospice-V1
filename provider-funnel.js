'use strict';
/**
 * Provider Funnel Intelligence V1 — what happened, inside Best Hospice, to the
 * referrals we sent one provider.
 *
 * DELIBERATELY COUNTS-FIRST
 * There is no response rate, no admission rate, no median response time, no
 * trend, no score, rank, grade or percentile, and no cross-provider comparison
 * of any kind. Read-only production validation established why:
 *
 *   - 87.46% of outcomes sit at the system default 'new'
 *   - only 7 of 37 providers have ever recorded a single response, and one
 *     provider accounts for 69.9% of all responses
 *   - the median time to a first status update is 5.0 days, with 40.7% of
 *     updates arriving more than a week after the referral, so that figure
 *     measures dashboard habits rather than responsiveness to families
 *   - 4 provider-lead pairs have ever been admitted, 3 of which were later
 *     reverted, leaving 1 current admission platform-wide
 *
 * Percentages over those distributions would be arithmetically correct and
 * practically misleading. Counts are not.
 *
 * PROVIDER-PRIVATE BY CONSTRUCTION
 * Every query filters on the single providerId the caller supplies, which the
 * future endpoint will take from the authenticated provider context and never
 * from a request parameter. No query aggregates across providers, and the
 * response carries no consumer name, email, phone, free text, session id or
 * identifier of any kind - only counts.
 *
 * A LEAF
 * No CMS service, no Market Intelligence, no Competitors, no Quality, no
 * ConsumerSearchEvent, no routing or eligibility code. This module reads six
 * tables and returns numbers.
 *
 * WHAT THE NUMBERS DO AND DO NOT MEAN
 * "Referrals sent" means Best Hospice sent a notification and the email
 * provider accepted it. There is no delivery, bounce or open data anywhere in
 * the system - no SendGrid event webhook exists - so nothing here may be called
 * received, delivered or read.
 *
 * "No response recorded" means no status update was made in Best Hospice. It
 * does NOT mean the provider failed to contact the family: a provider who
 * phones a family within the hour and never touches the dashboard is
 * indistinguishable, in this data, from one who did nothing.
 */

// The three windows the product supports. A closed set: an unrecognised value
// fails closed rather than silently defaulting, so a typo in a caller can never
// quietly widen or narrow what a provider is shown.
const FUNNEL_WINDOWS = Object.freeze({
  '30d': { key: '30d', label: 'Last 30 days', days: 30 },
  '90d': { key: '90d', label: 'Last 90 days', days: 90 },
  all: { key: 'all', label: 'All time', days: null }
});

const FUNNEL_STATUS = Object.freeze({
  OK: 'ok',
  INVALID_WINDOW: 'invalid_window',
  INVALID_PROVIDER: 'invalid_provider'
});

// The four buckets the provider dashboard already uses, in display order.
//
// Six statuses collapse into four labels, exactly as LEAD_OUTCOME_LABELS in
// server.js and the dashboard's own status picker do. `qualified` and
// `no_response` are never surfaced as separate categories: the picker cannot
// set either, and production currently holds 0 `qualified` rows against 8
// historical events, so a provider would not recognise a category they cannot
// choose.
//
// NOTE ON 'not_a_fit': its shipped label is "Not a True Lead", and
// `no_response` carries the SAME label. That is why `no_response` counts as a
// RESPONSE below - it is a deliberate provider assertion that the lead was not
// real, not a record of silence.
const OUTCOME_BUCKETS = Object.freeze([
  Object.freeze({ key: 'new', label: 'Received', sourceStatuses: Object.freeze(['new']) }),
  Object.freeze({ key: 'contacted', label: 'Contacted', sourceStatuses: Object.freeze(['contacted', 'qualified']) }),
  Object.freeze({ key: 'admitted', label: 'Admitted', sourceStatuses: Object.freeze(['admitted']) }),
  Object.freeze({ key: 'not_a_fit', label: 'Not a True Lead', sourceStatuses: Object.freeze(['not_a_fit', 'no_response']) })
]);

// 'all' has no lower bound. A sentinel far below any possible Lead.createdAt is
// used instead of a NULL parameter so the timestamp comparison has one shape in
// every window and cannot be affected by parameter-type inference.
const NO_LOWER_BOUND = new Date(0);

const METHODOLOGY = Object.freeze({
  referralDefinition:
    'A referral is one family request that Best Hospice sent to this provider. Counted once per request even when '
    + 'a follow-up notification with extra details was sent for the same request.',
  deliveryLimitation:
    'Best Hospice records that the email was accepted for delivery. It does not record whether the message reached '
    + 'an inbox, was opened, or was read.',
  responseDefinition:
    'A response is any status update made for that referral in Best Hospice - Contacted, Admitted or Not a True '
    + 'Lead. A referral still showing Received has no recorded update.',
  noResponseDefinition:
    'No response recorded means no status update was made in Best Hospice. It does not mean the provider did not '
    + 'contact the family. A provider who contacted a family without updating the status here appears in this group.',
  cohortDefinition:
    'A referral belongs to the period in which the family submitted their request, and is shown with whatever '
    + 'status it carries now. Recent referrals may not have reached an outcome yet.',
  statusCurrentOnly:
    'Every count reflects the status a referral carries now. A status that was changed, including one changed away '
    + 'from Admitted, is counted where it stands today.',
  limitations: Object.freeze([
    'These are Best Hospice records only, and reflect work recorded in this dashboard.',
    'Contact made outside Best Hospice without a status update appears as no response recorded.',
    'Best Hospice does not calculate a score, rank, grade or percentile from these counts.',
    'These counts are never compared with another provider.'
  ])
});

const emptyFunnel = (status, detail) => ({
  status,
  window: null,
  volume: null,
  engagement: null,
  outcomes: null,
  methodology: null,
  detail
});

function resolveWindow(windowKey, now) {
  // A STRING only. Without the type check `['30d']` would resolve, because
  // Array.prototype.toString joins a single element to exactly '30d' - the
  // right window, but by accident, and the option contract is a string.
  if (typeof windowKey !== 'string') return null;
  const spec = Object.prototype.hasOwnProperty.call(FUNNEL_WINDOWS, windowKey)
    ? FUNNEL_WINDOWS[windowKey]
    : null;
  if (!spec) return null;
  const to = now;
  const from = spec.days === null ? null : new Date(to.getTime() - spec.days * 24 * 60 * 60 * 1000);
  return {
    key: spec.key,
    label: spec.label,
    from: from ? from.toISOString() : null,
    to: to.toISOString(),
    cohortBasis: 'lead_created_at',
    // Not part of the response: the value actually bound into SQL.
    _boundary: from || NO_LOWER_BOUND
  };
}

/**
 * @param prisma      a PrismaClient
 * @param providerId  the provider whose OWN referrals are being counted. The
 *                    future endpoint derives this from the authenticated
 *                    provider context; it must never come from a request
 *                    parameter.
 * @param options     { window: '30d'|'90d'|'all', now?: Date }
 *                    `now` exists so window boundaries are testable; it
 *                    defaults to the current time.
 */
async function buildProviderFunnel(prisma, providerId, options = {}) {
  const id = typeof providerId === 'string' ? providerId.trim() : '';
  if (!id) {
    return emptyFunnel(FUNNEL_STATUS.INVALID_PROVIDER, 'No provider was supplied.');
  }

  const now = options.now instanceof Date ? options.now : new Date();
  const win = resolveWindow(options.window, now);
  if (!win) {
    return emptyFunnel(FUNNEL_STATUS.INVALID_WINDOW,
      `Window must be one of: ${Object.keys(FUNNEL_WINDOWS).join(', ')}.`);
  }
  const boundary = win._boundary;

  // ---- query 1: volume ---------------------------------------------------
  // Three scalars from one statement.
  //
  // Every count is DISTINCT on leadId, never COUNT(*). A single referral
  // legitimately produces TWO LeadNotification rows - the initial send and the
  // follow-up when the family adds details - and ProviderImpression has no
  // unique constraint, so raw row counts overstate. Production measured that
  // overstatement at 8.1% of pairs, affecting 21 of 38 active providers.
  //
  // couldNotBeDelivered deliberately excludes any pair that ALSO has a
  // successful send: a failure followed by a success is a delivered referral,
  // not a failed one. Production currently holds zero failed rows, so this
  // branch is unexercised there - which is exactly why it needs a test.
  const [volumeRow] = await prisma.$queryRaw`
    WITH sent AS (
      SELECT DISTINCT n."leadId" AS lead_id
      FROM "LeadNotification" n
      JOIN "Lead" l ON l.id = n."leadId"
      WHERE n."providerId" = ${id}
        AND n.status = 'sent'
        AND l."createdAt" >= ${boundary}
    ),
    failed_only AS (
      SELECT DISTINCT n."leadId" AS lead_id
      FROM "LeadNotification" n
      JOIN "Lead" l ON l.id = n."leadId"
      WHERE n."providerId" = ${id}
        AND n.status = 'failed'
        AND l."createdAt" >= ${boundary}
        AND NOT EXISTS (
          SELECT 1 FROM "LeadNotification" s
          WHERE s."providerId" = ${id}
            AND s."leadId" = n."leadId"
            AND s.status = 'sent'
        )
    ),
    matched AS (
      SELECT DISTINCT i."leadId" AS lead_id
      FROM "ProviderImpression" i
      JOIN "Lead" l ON l.id = i."leadId"
      WHERE i."providerId" = ${id}
        AND l."createdAt" >= ${boundary}
    )
    SELECT (SELECT count(*)::int FROM sent)        AS referrals_sent,
           (SELECT count(*)::int FROM failed_only) AS could_not_be_delivered,
           (SELECT count(*)::int FROM matched)     AS times_matched
  `;

  // ---- query 2: status breakdown -----------------------------------------
  // The four display buckets, grouped in PostgreSQL. One statement, not one per
  // status.
  //
  // LEFT JOIN so a sent referral with NO LeadOutcome row still appears. Those
  // land in 'new' / Received, which is the documented choice: from the
  // provider's side a referral with no recorded update is indistinguishable
  // from one sitting at 'new', and it keeps the four buckets summing exactly to
  // referralsSent. Production has 36 such pairs out of 1,703.
  //
  // The bucket is the single source of truth for whether a referral counts as
  // responded - responded is derived from the bucket, not from the raw status.
  // That way an unrecognised future status falls into Received AND counts as no
  // response, rather than splitting the two derivations and breaking the
  // invariant that responses + noResponse = referralsSent.
  const bucketRows = await prisma.$queryRaw`
    WITH sent AS (
      SELECT DISTINCT n."leadId" AS lead_id
      FROM "LeadNotification" n
      JOIN "Lead" l ON l.id = n."leadId"
      WHERE n."providerId" = ${id}
        AND n.status = 'sent'
        AND l."createdAt" >= ${boundary}
    ),
    bucketed AS (
      SELECT s.lead_id,
             CASE
               WHEN o.status IN ('contacted', 'qualified')   THEN 'contacted'
               WHEN o.status = 'admitted'                    THEN 'admitted'
               WHEN o.status IN ('not_a_fit', 'no_response')  THEN 'not_a_fit'
               ELSE 'new'
             END AS bucket
      FROM sent s
      LEFT JOIN "LeadOutcome" o
        ON o."leadId" = s.lead_id
       AND o."providerId" = ${id}
    )
    SELECT bucket, count(*)::int AS n
    FROM bucketed
    GROUP BY bucket
  `;

  const countByBucket = new Map(bucketRows.map((r) => [r.bucket, Number(r.n) || 0]));
  const outcomes = OUTCOME_BUCKETS.map((b) => ({
    key: b.key,
    label: b.label,
    count: countByBucket.get(b.key) || 0
  }));

  const referralsSent = Number(volumeRow ? volumeRow.referrals_sent : 0) || 0;
  const noResponseRecorded = countByBucket.get('new') || 0;
  const responsesRecorded = referralsSent - noResponseRecorded;

  return {
    status: FUNNEL_STATUS.OK,
    window: {
      key: win.key,
      label: win.label,
      from: win.from,
      to: win.to,
      cohortBasis: win.cohortBasis
    },
    volume: {
      referralsSent,
      timesMatched: Number(volumeRow ? volumeRow.times_matched : 0) || 0,
      couldNotBeDelivered: Number(volumeRow ? volumeRow.could_not_be_delivered : 0) || 0
    },
    engagement: {
      responsesRecorded,
      noResponseRecorded
    },
    outcomes,
    methodology: METHODOLOGY,
    detail: null
  };
}

module.exports = {
  buildProviderFunnel,
  FUNNEL_WINDOWS,
  FUNNEL_STATUS,
  OUTCOME_BUCKETS,
  METHODOLOGY
};
