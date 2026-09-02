'use strict';
/**
 * My Market Phase 1 — CMS hospice service-area overlap.
 *
 * MARKET DEFINITION
 * A hospice provider's market is the set of ZIP codes its resolved CmsFacility
 * serves, exactly as CMS publishes them in CmsFacilityServiceArea.
 *
 * COMPETITOR DEFINITION
 * Another CmsFacility with source = cms_hospice that serves at least one of
 * those ZIPs. The provider's own facility is excluded, and so is every facility
 * from any other CMS source.
 *
 * WHAT THIS IS NOT
 * Overlap is a supply proxy, nothing more. It does not imply referral
 * relationships, patient volume, geographic exclusivity, or quality. It is not
 * derived from mileage, city, county, state, provider-name similarity, Best
 * Hospice coverage radius, Best Hospice lead geography, or any fuzzy match.
 * Nothing here consults Best Hospice subscription or payment status.
 *
 * Identity must resolve first. This module reuses cms-provider-resolver.js
 * rather than reimplementing Provider -> ProviderExternalIdentity -> CmsFacility,
 * so there is exactly one identity path in the codebase and no fuzzy fallback.
 *
 * Provider.internalRole has no effect here, exactly as in the resolver.
 *
 * SNAPSHOT SEMANTICS
 * CmsFacility and CmsFacilityServiceArea are current state, updated in place as
 * CMS republishes. This is therefore the market according to the CURRENT ingested
 * snapshot. No historical reconstruction is attempted and no history table exists.
 */
const { resolveProviderCmsContext, CMS_RESOLVER_STATUS } = require('./cms-provider-resolver');

// The only source this phase serves. Kept explicit so a future home-health market
// is an addition, not a loosening.
const MARKET_SOURCE = 'cms_hospice';

const CMS_MARKET_STATUS = Object.freeze({
  ...CMS_RESOLVER_STATUS,
  NO_SERVICE_AREA: 'no_service_area',
  MARKET_UNAVAILABLE: 'market_unavailable'
});

// One documented precision for every percentage in this module: 2 decimal places,
// half-up on the scaled integer. Deterministic across platforms.
const pct = (numerator, denominator) =>
  denominator > 0 ? Math.round((numerator / denominator) * 10000) / 100 : 0;
const round2 = (value) => Math.round(value * 100) / 100;

const emptyMarket = (status, resolved, detail) => ({
  status,
  provider: resolved && resolved.provider ? { id: resolved.provider.id, name: resolved.provider.name } : null,
  facility: resolved && resolved.facility
    ? { source: resolved.facility.source, ccn: resolved.facility.ccn, name: resolved.facility.name,
        city: resolved.facility.city, state: resolved.facility.state }
    : null,
  market: null,
  zipDensity: null,
  competitors: null,
  freshness: (resolved && resolved.freshness) || null,
  detail
});

/**
 * @param prisma      a PrismaClient
 * @param providerId  the ONLY authoritative input. Care type, CMS source, CCN,
 *                    facility and service area are all derived from the database.
 */
async function buildProviderCmsMarket(prisma, providerId) {
  const resolved = await resolveProviderCmsContext(prisma, providerId);

  // Propagate the resolver's own states verbatim rather than collapsing them into
  // one ambiguous failure: "we have not matched you yet" and "your identity is
  // ambiguous" are different things to a human.
  if (resolved.status !== CMS_RESOLVER_STATUS.RESOLVED) {
    return emptyMarket(resolved.status, resolved, resolved.detail);
  }
  if (resolved.facility.source !== MARKET_SOURCE) {
    return emptyMarket(CMS_MARKET_STATUS.MARKET_UNAVAILABLE, resolved,
      `Market overlap is not implemented for source "${resolved.facility.source}".`);
  }

  const ownZips = resolved.serviceArea.zips;
  const providerZipCount = ownZips.length;
  if (providerZipCount === 0) {
    // No service area means no market. Deliberately NOT substituted with the
    // facility's city or state, which would invent a market CMS never published.
    return emptyMarket(CMS_MARKET_STATUS.NO_SERVICE_AREA, resolved,
      'This facility has no CMS service-area ZIP codes in the current snapshot.');
  }

  const source = resolved.facility.source;
  const ccn = resolved.facility.ccn;

  // ---- overlap, in ONE aggregate query ------------------------------------
  // Raw SQL is used deliberately. The whole computation is a set operation:
  // self-join CmsFacilityServiceArea on zip, group by facility, count. Expressing
  // it in Prisma would mean pulling every matching service-area row into Node and
  // grouping there, or issuing one query per competitor - an N+1 over a table that
  // already holds ~342k rows. @@index([source, zip]) is exactly the index this
  // join wants, and the denormalised source column keeps it a single-table scan.
  //
  // Every value is parameterised through the tagged template. No caller input is
  // interpolated into SQL text.
  const competitorRows = await prisma.$queryRaw`
    WITH own AS (
      SELECT f.id AS fid, sa.zip
      FROM "CmsFacility" f
      JOIN "CmsFacilityServiceArea" sa
        ON sa."facilityId" = f.id AND sa.source = f.source
      WHERE f.source = ${source} AND f.ccn = ${ccn}
    ),
    own_facility AS (SELECT DISTINCT fid FROM own),
    shared AS (
      SELECT sa."facilityId" AS fid, sa.zip
      FROM "CmsFacilityServiceArea" sa
      JOIN own ON own.zip = sa.zip
      WHERE sa.source = ${source}
        AND sa."facilityId" <> (SELECT fid FROM own_facility)
    ),
    totals AS (
      SELECT sa."facilityId" AS fid, count(*)::int AS total
      FROM "CmsFacilityServiceArea" sa
      WHERE sa.source = ${source}
        AND sa."facilityId" IN (SELECT DISTINCT fid FROM shared)
      GROUP BY sa."facilityId"
    )
    SELECT f.ccn                                   AS ccn,
           f.name                                  AS name,
           f.city                                  AS city,
           f.state                                 AS state,
           count(*)::int                           AS shared_zip_count,
           array_agg(shared.zip ORDER BY shared.zip) AS shared_zips,
           totals.total                            AS competitor_zip_count
    FROM shared
    JOIN "CmsFacility" f ON f.id = shared.fid AND f.source = ${source}
    JOIN totals ON totals.fid = shared.fid
    GROUP BY f.ccn, f.name, f.city, f.state, totals.total
  `;

  // ---- per-ZIP density, in ONE aggregate query ----------------------------
  const densityRows = await prisma.$queryRaw`
    WITH own AS (
      SELECT f.id AS fid, sa.zip
      FROM "CmsFacility" f
      JOIN "CmsFacilityServiceArea" sa
        ON sa."facilityId" = f.id AND sa.source = f.source
      WHERE f.source = ${source} AND f.ccn = ${ccn}
    ),
    own_facility AS (SELECT DISTINCT fid FROM own)
    SELECT own.zip AS zip,
           count(sa."facilityId")::int AS competitor_count
    FROM own
    LEFT JOIN "CmsFacilityServiceArea" sa
      ON sa.zip = own.zip
     AND sa.source = ${source}
     AND sa."facilityId" <> (SELECT fid FROM own_facility)
    GROUP BY own.zip
    ORDER BY own.zip ASC
  `;

  const competitors = competitorRows.map((r) => {
    const sharedZipCount = Number(r.shared_zip_count);
    const competitorZipCount = Number(r.competitor_zip_count);
    return {
      source,
      ccn: r.ccn,
      name: r.name,
      city: r.city,
      state: r.state,
      sharedZipCount,
      providerZipCount,
      competitorZipCount,
      providerOverlapPct: pct(sharedZipCount, providerZipCount),
      competitorOverlapPct: pct(sharedZipCount, competitorZipCount),
      // Already ordered by the array_agg ORDER BY; the schema's
      // @@unique([facilityId, zip]) rules out duplicates, so no dedupe is needed.
      sharedZips: r.shared_zips
    };
  });

  // Deterministic ranking. sharedZipCount is an integer and is the primary
  // signal, so ties are broken before any float comparison decides an order.
  competitors.sort((a, b) =>
    b.sharedZipCount - a.sharedZipCount
    || b.providerOverlapPct - a.providerOverlapPct
    || b.competitorOverlapPct - a.competitorOverlapPct
    || a.name.localeCompare(b.name)
    || a.ccn.localeCompare(b.ccn));

  const zipDensity = densityRows.map((r) => ({ zip: r.zip, competitorCount: Number(r.competitor_count) }));
  const totalSharedZipRelationships = competitors.reduce((n, c) => n + c.sharedZipCount, 0);
  const densitySum = zipDensity.reduce((n, z) => n + z.competitorCount, 0);

  return {
    status: CMS_MARKET_STATUS.RESOLVED,
    provider: { id: resolved.provider.id, name: resolved.provider.name },
    facility: {
      source: resolved.facility.source, ccn: resolved.facility.ccn, name: resolved.facility.name,
      city: resolved.facility.city, state: resolved.facility.state
    },
    market: {
      providerZipCount,
      overlappingFacilityCount: competitors.length,
      totalSharedZipRelationships,
      averageCompetitorsPerProviderZip: round2(densitySum / providerZipCount),
      highestOverlapSharedZipCount: competitors.length ? competitors[0].sharedZipCount : 0
    },
    zipDensity,
    competitors,
    freshness: resolved.freshness,
    detail: null
  };
}

module.exports = { buildProviderCmsMarket, CMS_MARKET_STATUS, MARKET_SOURCE };
