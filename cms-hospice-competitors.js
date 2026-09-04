'use strict';
/**
 * Competitor Intelligence V1 Phase A — the competitor landscape.
 *
 * THE QUESTION THIS ANSWERS
 * "Which other Medicare-certified hospices serve the same ZIP codes I do, how
 * much of my footprint does each of them touch, and how much has CMS actually
 * published about them?" Nothing more. Per-measure head-to-head comparison is a
 * later, separately loaded concern and is deliberately absent here.
 *
 * COMPETITOR DEFINITION — REUSED, NOT REDEFINED
 * A competitor is another CmsFacility with source = cms_hospice that serves at
 * least one of the ZIP codes CMS publishes for the provider's own facility. That
 * is My Market's definition verbatim, and this module obtains the competitor set
 * by CALLING buildProviderCmsMarket() rather than by reimplementing the overlap
 * query. There is therefore exactly one market definition in the codebase, and
 * identity still resolves through cms-provider-resolver.js (transitively, via the
 * market module) with no second identity path and no fuzzy fallback.
 *
 * ORDERING IS ALSO REUSED, NOT REDEFINED
 * My Market already ranks competitors by sharedZipCount DESC, then
 * providerOverlapPct DESC, then competitorOverlapPct DESC, then facility name
 * ASC, then CCN ASC. This module PRESERVES that order and never re-sorts, so the
 * two features can never disagree about who the leading competitor is. The
 * contract is pinned by assertions in scripts/test-cms-hospice-competitors.js
 * rather than by a duplicate comparator here.
 *
 * Quality data is fetched AFTER ordering is fixed and is never an input to it.
 *
 * QUALITY AVAILABILITY IS NOT A QUALITY SCORE
 * qualityAvailability.publishedMeasureCount answers exactly one question: how
 * many of the surfaced CMS measures CMS published a usable value for at this
 * hospice. It is not a score, not a completeness grade, not a performance
 * statement, and not a ranking input. A hospice CMS withheld data for is not a
 * worse hospice; it is a hospice CMS withheld data for.
 *
 * SUPPRESSED DATA IS NOT ZERO
 * A measure counts as published only under the existing Quality semantics -
 * suppressed = false AND valueNumeric IS NOT NULL. Suppressed and missing rows
 * are excluded from the count, never imputed and never treated as zero. When no
 * release carries measurements at all, qualityAvailability is null rather than a
 * fabricated "0 of 10".
 *
 * PARTNER BADGE IS A BOOLEAN AND NOTHING ELSE
 * bestHospicePartner comes only from a human-accepted ProviderExternalIdentity
 * row whose linked Provider is not an internal account. There is no fuzzy name,
 * city or ZIP matching, and the lookup projects ONLY externalId, so no Provider
 * id, email, contact detail, billing mode, subscription, plan or lead setting can
 * reach the response even by accident.
 *
 * WHAT THIS IS NOT
 * Overlap is a supply proxy. It does not imply market share, patient volume,
 * referral relationships, revenue, utilization, payment or causation, and there
 * is no proprietary Best Hospice competitor score, rank or grade. Nothing here
 * consults Best Hospice subscription, billing or lead data.
 *
 * CONSUMER ROUTING IS UNTOUCHED
 * CmsFacilityServiceArea is CMS market intelligence only. This module is strictly
 * read-only: it performs no writes of any kind, and in particular never writes to
 * Provider.serviceZipCodes or Provider.serviceRadiusKm, which are the only inputs
 * to consumer lead eligibility.
 */
const { buildProviderCmsMarket, CMS_MARKET_STATUS } = require('./cms-hospice-market');

// The only source this phase serves. Kept explicit so a future home-health
// competitor view is an addition, not a loosening.
const COMPETITOR_SOURCE = 'cms_hospice';

// No new statuses. Every failure mode is one My Market or the resolver already
// names, so a provider is never shown two different words for one situation.
const CMS_COMPETITOR_STATUS = Object.freeze({ ...CMS_MARKET_STATUS });

const emptyCompetitors = (status, market, detail) => ({
  status,
  provider: (market && market.provider) || null,
  facility: (market && market.facility) || null,
  landscape: null,
  competitors: null,
  freshness: (market && market.freshness) || null,
  methodology: null,
  detail
});

const METHODOLOGY = Object.freeze({
  competitorDefinition:
    'A competitor is another Medicare-certified hospice that CMS reports as serving at least one of the same ZIP codes '
    + 'as this provider.',
  ordering:
    'Competitors are ordered by CMS service-area overlap: the number of shared ZIP codes first, then the share of each '
    + "hospice's footprint that overlap represents. CMS quality results never affect this order.",
  overlapMeaning:
    'Shared ZIP codes describe overlapping CMS-reported service footprints. Overlap is a supply measure only.',
  qualityAvailabilityMeaning:
    'CMS published this many of the surfaced measures for this hospice. It is a count of what CMS released, not a '
    + 'quality score, a completeness score, or a statement about how good the hospice is.',
  suppression:
    'A measure counts as published only where CMS released a usable value. Suppressed and missing measures are '
    + 'excluded from the count and are never treated as zero.',
  partnerBadge:
    'A hospice is marked as a Best Hospice partner only where a person has verified that it is the same organisation '
    + 'as a Best Hospice provider record. Names, cities and ZIP codes are never used to guess a match.',
  consumerLeadSeparation:
    'CMS service-area data is market intelligence only. It does not determine which providers receive Best Hospice '
    + 'consumer enquiries.',
  notRepresenting: Object.freeze([
    'market share',
    'patient volume',
    'referral relationships',
    'revenue',
    'Medicare utilization or payment',
    'causation',
    'a proprietary Best Hospice competitor score, rank or grade'
  ])
});

/**
 * @param prisma      a PrismaClient
 * @param providerId  the ONLY authoritative input. Care type, CMS source, CCN,
 *                    facility, service area and competitor set are all derived
 *                    from the database.
 */
async function buildProviderCmsCompetitors(prisma, providerId) {
  // Round trips 1-9. Also the single identity path: this resolves the provider
  // through cms-provider-resolver.js and fails closed on every unresolved state,
  // propagating the resolver's own wording rather than collapsing several very
  // different situations into one ambiguous failure.
  const market = await buildProviderCmsMarket(prisma, providerId);
  if (market.status !== CMS_MARKET_STATUS.RESOLVED) {
    return emptyCompetitors(market.status, market, market.detail);
  }
  if (market.facility.source !== COMPETITOR_SOURCE) {
    return emptyCompetitors(CMS_COMPETITOR_STATUS.MARKET_UNAVAILABLE, market,
      `Competitor intelligence is not implemented for source "${market.facility.source}".`);
  }

  const source = market.facility.source;
  // Order is My Market's, already applied. Never re-sorted below.
  const ranked = market.competitors;
  const ccns = ranked.map((c) => c.ccn);

  // ---- round trip 10: ONE bulk enrichment query --------------------------
  // Everything competitor-shaped that My Market does not already return, for
  // ALL competitors at once. Four things are folded into a single statement so
  // the round-trip count stays flat and so the release used for the published
  // counts is chosen in the same snapshot the counts are taken from:
  //
  //   rel      the newest release that actually HAS measurements. Not simply the
  //            newest release: the facility roster and the quality files are
  //            ingested by separate authorized steps, so quality can legitimately
  //            lag by one release. This is cms-hospice-quality.js's release
  //            selection, reproduced here as a CTE because it must pin the count.
  //   surfaced how many measures are configured for display - the "of Y".
  //   fac      the competitor facilities, giving the ZIP My Market does not
  //            select. ownershipType is deliberately NOT read: V1 makes no
  //            ownership claims.
  //   pub      per-facility count of measures CMS published, grouped in
  //            PostgreSQL. suppressed = FALSE AND valueNumeric IS NOT NULL is the
  //            existing Quality definition of "published", so a withheld measure
  //            is excluded rather than counted as a zero.
  //
  // LEFT JOIN fac ON TRUE keeps exactly one row when there are no competitors at
  // all, so a provider with an empty market still gets the release and the
  // surfaced count instead of an empty result set.
  //
  // Every value is parameterised through the tagged template. No caller input is
  // interpolated into SQL text, and the competitor CCNs are database-derived.
  const enrichmentRows = await prisma.$queryRaw`
    WITH rel AS (
      SELECT r.id AS id, r."releaseKey" AS release_key, r."capturedAt" AS captured_at
      FROM "CmsRelease" r
      WHERE r.source = ${source}
        AND EXISTS (
          SELECT 1 FROM "CmsFacilityMeasure" m
          WHERE m."releaseId" = r.id AND m.source = ${source})
      ORDER BY r."releaseKey" DESC
      LIMIT 1
    ),
    surfaced AS (
      SELECT count(*)::int AS n
      FROM "CmsMeasureDefinition" d
      WHERE d.source = ${source} AND d.surfaced = TRUE
    ),
    fac AS (
      SELECT f.id AS id, f.ccn AS ccn, f.zip AS zip
      FROM "CmsFacility" f
      WHERE f.source = ${source} AND f.ccn = ANY(${ccns}::text[])
    ),
    pub AS (
      SELECT m."facilityId" AS fid, count(*)::int AS n
      FROM "CmsFacilityMeasure" m
      JOIN fac ON fac.id = m."facilityId"
      JOIN "CmsMeasureDefinition" d
        ON d.source = m.source AND d."measureCode" = m."measureCode"
      WHERE m.source = ${source}
        AND m."releaseId" = (SELECT id FROM rel)
        AND d.surfaced = TRUE
        AND m.suppressed = FALSE
        AND m."valueNumeric" IS NOT NULL
      GROUP BY m."facilityId"
    )
    SELECT (SELECT id FROM rel)           AS release_id,
           (SELECT release_key FROM rel)  AS release_key,
           (SELECT captured_at FROM rel)  AS captured_at,
           (SELECT n FROM surfaced)       AS surfaced_count,
           fac.ccn                        AS ccn,
           fac.zip                        AS zip,
           COALESCE(pub.n, 0)             AS published_count
    FROM (SELECT 1) AS one
    LEFT JOIN fac ON TRUE
    LEFT JOIN pub ON pub.fid = fac.id
  `;

  // ---- round trip 11: ONE bulk verified-partner lookup -------------------
  // @@unique([source, externalId]) makes CCN -> identity a single indexed
  // lookup, so all competitors resolve in one query.
  //
  // Four conditions, all pushed into SQL rather than filtered in JavaScript:
  //   identifierType = 'ccn'    the identifier this source publishes.
  //   verifiedAt IS NOT NULL    the repo's acceptance marker. The identity
  //                             importer writes it from the human reviewer's
  //                             reviewedAt, so a null means no person ever
  //                             accepted the mapping.
  //   provider.internalRole     null only. An internal reference account can hold
  //                             a perfectly valid verified identity; badging it
  //                             would show a real hospice our own test record
  //                             dressed as a partner organisation.
  //
  // select is externalId ONLY. The badge is a boolean, so there is no Provider
  // id, email, phone, billing mode, subscription, plan tier or lead setting in
  // the result set to leak - not by mistake and not by a later edit here.
  const partnerRows = await prisma.providerExternalIdentity.findMany({
    where: {
      source,
      identifierType: 'ccn',
      externalId: { in: ccns },
      verifiedAt: { not: null },
      provider: { internalRole: null }
    },
    select: { externalId: true }
  });
  const partnerCcns = new Set(partnerRows.map((r) => r.externalId));

  const header = enrichmentRows[0] || {};
  const releaseId = header.release_id || null;
  const surfacedMeasureCount = Number(header.surfaced_count) || 0;
  // Availability needs both a release that carries measurements and at least one
  // measure configured for display. Without either there is no honest "X of Y" to
  // state, and "0 of 0" would read as a finding about the hospice.
  const availabilityKnown = !!releaseId && surfacedMeasureCount > 0;

  const enrichmentByCcn = new Map();
  for (const row of enrichmentRows) {
    if (row.ccn) enrichmentByCcn.set(row.ccn, row);
  }

  const competitors = ranked.map((c) => {
    const extra = enrichmentByCcn.get(c.ccn);
    return {
      source: c.source,
      ccn: c.ccn,
      name: c.name,
      city: c.city,
      state: c.state,
      zip: extra ? extra.zip : null,
      sharedZipCount: c.sharedZipCount,
      providerZipCount: c.providerZipCount,
      competitorZipCount: c.competitorZipCount,
      providerOverlapPct: c.providerOverlapPct,
      competitorOverlapPct: c.competitorOverlapPct,
      qualityAvailability: availabilityKnown
        ? {
            publishedMeasureCount: extra ? Number(extra.published_count) : 0,
            surfacedMeasureCount
          }
        : null,
      bestHospicePartner: partnerCcns.has(c.ccn)
      // sharedZips is deliberately NOT carried through. It belongs to the
      // head-to-head detail view; on a large market it is thousands of strings
      // nobody reads on the list.
    };
  });

  const top = competitors.length ? competitors[0] : null;

  return {
    status: CMS_COMPETITOR_STATUS.RESOLVED,
    provider: market.provider,
    facility: market.facility,
    landscape: {
      // Restated from My Market's own output so the provider can see the
      // competitor list is drawn from exactly the market they were already shown.
      providerZipCount: market.market.providerZipCount,
      overlappingFacilityCount: market.market.overlappingFacilityCount,
      totalSharedZipRelationships: market.market.totalSharedZipRelationships,
      averageCompetitorsPerProviderZip: market.market.averageCompetitorsPerProviderZip,
      highestOverlapSharedZipCount: market.market.highestOverlapSharedZipCount,
      // Read off the ranked list rather than recomputed, so "the top competitor"
      // in the headline is always the hospice sitting first in the table.
      topCompetitorSharedZipCount: top ? top.sharedZipCount : 0,
      topCompetitorProviderOverlapPct: top ? top.providerOverlapPct : 0,
      // The shared "of Y" denominator behind every qualityAvailability. Exposed
      // so a consumer can tell "CMS published nothing" apart from "no measures
      // are configured for display".
      surfacedMeasureCount
    },
    competitors,
    freshness: {
      ...market.freshness,
      qualityRelease: releaseId
        ? { releaseKey: header.release_key, capturedAt: header.captured_at }
        : null
    },
    methodology: METHODOLOGY,
    detail: null
  };
}

module.exports = {
  buildProviderCmsCompetitors,
  CMS_COMPETITOR_STATUS,
  COMPETITOR_SOURCE,
  METHODOLOGY
};
