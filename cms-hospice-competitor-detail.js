'use strict';
/**
 * Competitor Intelligence V1 Phase C — direct head-to-head CMS quality
 * comparison between the authenticated provider and ONE overlapping hospice.
 *
 * THE QUESTION THIS ANSWERS
 * "On each measure CMS publishes, how does my hospice's value compare with this
 * specific hospice's value?" That is a two-value comparison. It is NOT the
 * question Quality Intelligence answers, which is "how does my value sit against
 * the MEDIAN of every overlapping hospice".
 *
 * WHY THE PEER VERDICT CANNOT BE REUSED
 * cms-hospice-quality.js's `verdict` and `favorable` describe the provider
 * against a peer median over a population with a minimum size. A provider can be
 * comfortably above that median while this one competitor is still ahead of
 * them. Reusing those fields here would be a category error, so this module
 * computes its own two-value comparison and shares only what genuinely is
 * shared: the DIRECTION constants, so the two modules cannot disagree about what
 * 'lower_better' means.
 *
 * THE OVERLAP SET IS THE AUTHORIZATION BOUNDARY
 * A provider may read quality detail for a hospice ONLY if that hospice appears
 * in their own CMS market, which is built by buildProviderCmsMarket() from
 * CMS-reported service-area overlap. Nothing else authorizes: not a shared city,
 * not a shared state, not a similar name, not the mere existence of the CMS
 * facility, not a ProviderExternalIdentity row, not partner status, and not a
 * service-area lookup done independently here. Without that rule this endpoint
 * would be an arbitrary lookup over the whole 6,669-row facility table.
 *
 * The provider's OWN facility is excluded by construction: My Market never
 * returns it as a competitor, so a provider cannot compare themselves with
 * themselves.
 *
 * ONE RELEASE, BOTH FACILITIES
 * Both hospices are pinned to the SAME releaseId - the newest CMS release that
 * actually CONTAINS measurements, which is not necessarily the newest release
 * overall, because the facility roster and the quality files are ingested by
 * separate authorized steps. Reading each facility's own newest data would
 * compare different measurement periods and silently produce a false result.
 *
 * SUPPRESSED IS NOT ZERO, AND NOT COMPARABLE
 * A measure counts as published only where suppressed = false AND valueNumeric
 * IS NOT NULL. If EITHER hospice lacks a published value the comparison is
 * 'unavailable'. A published value is never compared against a missing one, and
 * a missing one is never imputed as zero.
 *
 * WHAT THIS IS NOT
 * There is no score, rank, grade, percentile, composite, index or winner field,
 * and the summary counts are tallies of individual measures - nothing is derived
 * from them. Overlap is a supply proxy and implies no market share, patient
 * volume, referral relationship or revenue. Nothing here consults Best Hospice
 * subscription, billing or lead data, and CmsFacilityServiceArea remains market
 * intelligence that has never been an input to consumer lead eligibility.
 */
const { buildProviderCmsMarket, CMS_MARKET_STATUS } = require('./cms-hospice-market');
const { DIRECTION } = require('./cms-hospice-quality');
const { verifiedPartnerCcns } = require('./cms-partner-badge');

const DETAIL_SOURCE = 'cms_hospice';

// Exactly the shape CMS publishes: six characters, digits and uppercase letters,
// leading zeros significant. Validated, never normalised - silently upper-casing
// a caller's input would be accepting malformed input, and every CCN the UI ever
// sends comes straight back out of our own API already in this form.
const CCN_PATTERN = /^[0-9A-Z]{6}$/;

const CMS_COMPETITOR_DETAIL_STATUS = Object.freeze({
  ...CMS_MARKET_STATUS,
  INVALID_CCN: 'invalid_ccn',
  COMPETITOR_NOT_IN_MARKET: 'competitor_not_in_market',
  NO_QUALITY_DATA: 'no_quality_data'
});

// IMPORTANT — these names describe FAVOURABILITY, not arithmetic.
//
// PROVIDER_HIGHER means the provider's value is the better one for that measure.
// On a lower-is-better measure such as early live discharges that means the
// provider's NUMBER IS SMALLER. Anything rendering these values must take its
// wording from comparisonText, which describes the actual numbers, and never
// from the enum name.
const COMPARISON = Object.freeze({
  PROVIDER_HIGHER: 'provider_higher',
  COMPETITOR_HIGHER: 'competitor_higher',
  SAME: 'same',
  UNAVAILABLE: 'unavailable'
});

const LOWER_IS_BETTER_NOTE = 'Lower is better for this measure.';

const emptyDetail = (status, market, competitor, detail) => ({
  status,
  provider: (market && market.facility)
    ? { source: market.facility.source, ccn: market.facility.ccn, name: market.facility.name }
    : null,
  competitor: competitor || null,
  overlap: null,
  comparisonSummary: null,
  measures: null,
  freshness: (market && market.freshness) || null,
  methodology: null,
  detail
});

const METHODOLOGY = Object.freeze({
  comparisonDefinition:
    'Each measure is compared directly between the two hospices, using the values CMS published for both in the same '
    + 'CMS quality release.',
  peerMedianDistinction:
    'This is a direct comparison with one hospice. It is not the overlapping-hospice median shown in Quality '
    + 'Intelligence, and a hospice can sit above that median while another hospice is still ahead of it on a measure.',
  suppression:
    'A measure is compared only where CMS published a usable value for BOTH hospices. Where either value is '
    + 'suppressed or missing the measure is shown as not comparable. Missing values are never treated as zero and '
    + 'never compared against a published value.',
  direction:
    'Whether a higher or a lower value is better is read from the measure definition CMS documents, never inferred '
    + 'from the numbers.',
  overlapMeaning:
    'Shared ZIP codes describe overlapping CMS-reported service footprints. Overlap is a supply measure only.',
  consumerLeadSeparation:
    'CMS service-area data is market intelligence only. It does not determine which providers receive Best Hospice '
    + 'consumer enquiries.',
  noProprietaryScore:
    'The summary counts individual measures. Best Hospice does not calculate an overall competitor score, rank, '
    + 'grade or index from them, and neither hospice is declared better overall.',
  notRepresenting: Object.freeze([
    'market share',
    'patient volume',
    'referral relationships',
    'revenue',
    'Medicare utilization or payment',
    'causation',
    'an overall judgement about which hospice provides better care'
  ])
});

// Published means exactly what it means everywhere else in the CMS layer.
const publishedValue = (valueNumeric, suppressed) =>
  (suppressed === false && valueNumeric !== null && valueNumeric !== undefined
    ? Number(valueNumeric)
    : null);

/**
 * Direction-aware two-value comparison.
 *
 * Returns UNAVAILABLE unless BOTH values are published, so a published value is
 * never weighed against an absent one.
 */
function compareValues(providerValue, competitorValue, direction) {
  if (providerValue === null || competitorValue === null) return COMPARISON.UNAVAILABLE;
  if (providerValue === competitorValue) return COMPARISON.SAME;
  const providerFavourable = direction === DIRECTION.LOWER_BETTER
    ? providerValue < competitorValue
    : providerValue > competitorValue;
  return providerFavourable ? COMPARISON.PROVIDER_HIGHER : COMPARISON.COMPETITOR_HIGHER;
}

/**
 * Plain description of the ACTUAL NUMBERS, which is why it depends on direction:
 * on a lower-is-better measure the favourable side is the lower one. Deliberately
 * never says better, worse, wins, beats, stronger or superior.
 */
function comparisonSentence(comparison, direction) {
  const lowerIsBetter = direction === DIRECTION.LOWER_BETTER;
  if (comparison === COMPARISON.SAME) return 'Same value';
  if (comparison === COMPARISON.PROVIDER_HIGHER) {
    return lowerIsBetter ? 'Your value is lower' : 'Your value is higher';
  }
  if (comparison === COMPARISON.COMPETITOR_HIGHER) {
    return lowerIsBetter ? "Competitor's value is lower" : "Competitor's value is higher";
  }
  return 'Not comparable';
}

/**
 * @param prisma      a PrismaClient
 * @param providerId  the authenticated provider. The ONLY identity input.
 * @param rawCcn      the requested competitor CCN, straight from the route.
 *                    The only caller-supplied value anywhere in this module, and
 *                    it is validated and then checked against the provider's own
 *                    overlap set before it can reach any quality data.
 */
async function buildProviderCmsCompetitorDetail(prisma, providerId, rawCcn) {
  // Validate BEFORE touching the database. A malformed CCN is rejected on its
  // shape alone, so a caller cannot probe for facilities with it.
  const ccn = typeof rawCcn === 'string' ? rawCcn : '';
  if (!CCN_PATTERN.test(ccn)) {
    return emptyDetail(CMS_COMPETITOR_DETAIL_STATUS.INVALID_CCN, null, null,
      'A CMS certification number is six characters, digits and uppercase letters only.');
  }

  // Round trips 1-9. Also the single identity path, and the authorization set.
  const market = await buildProviderCmsMarket(prisma, providerId);
  if (market.status !== CMS_MARKET_STATUS.RESOLVED) {
    return emptyDetail(market.status, market, null, market.detail);
  }
  if (market.facility.source !== DETAIL_SOURCE) {
    return emptyDetail(CMS_COMPETITOR_DETAIL_STATUS.MARKET_UNAVAILABLE, market, null,
      `Competitor comparison is not implemented for source "${market.facility.source}".`);
  }

  // THE AUTHORIZATION CHECK. The requested hospice must be in this provider's own
  // CMS overlap set, and that entry is then the only source of overlap truth -
  // nothing about the relationship is recomputed here. Their own CCN is not in
  // this list, so a provider cannot compare themselves with themselves.
  const competitorEntry = market.competitors.find((c) => c.ccn === ccn);
  if (!competitorEntry) {
    return emptyDetail(CMS_COMPETITOR_DETAIL_STATUS.COMPETITOR_NOT_IN_MARKET, market, null,
      'That hospice does not share a CMS-reported service ZIP code with this provider.');
  }

  const source = market.facility.source;
  const ownCcn = market.facility.ccn;

  // ---- round trip 10: ONE bulk query for the whole comparison -------------
  // Every surfaced measure definition, LEFT JOINed to BOTH facilities' rows.
  // LEFT so a measure CMS published for neither hospice still comes back as a
  // definition with no values, rather than vanishing from the table.
  //
  // rel is the newest release that actually HAS measurements. Both LEFT JOINs
  // read `(SELECT id FROM rel)`, so the two facilities are pinned to ONE release
  // structurally - it is not possible to satisfy this query with rows from two
  // different releases.
  //
  // The cost is one grouped scan of a 10-row definition table joined twice
  // against @@index([source, releaseId, measureCode, facilityId]). It does not
  // grow with the number of measures, the number of competitors or the number of
  // shared ZIP codes.
  //
  // Every value is parameterised through the tagged template. The competitor CCN
  // has already been validated against CCN_PATTERN and matched against the
  // provider's own market before reaching here.
  const rows = await prisma.$queryRaw`
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
    own_fac AS (
      SELECT f.id AS id FROM "CmsFacility" f
      WHERE f.source = ${source} AND f.ccn = ${ownCcn}
    ),
    comp_fac AS (
      SELECT f.id AS id, f.zip AS zip FROM "CmsFacility" f
      WHERE f.source = ${source} AND f.ccn = ${ccn}
    )
    SELECT d."measureCode"       AS measure_code,
           d."cmsMeasureName"    AS cms_measure_name,
           d."shortLabel"        AS short_label,
           d.dimension           AS dimension,
           d.family              AS family,
           d."valueKind"         AS value_kind,
           d.direction           AS direction,
           d."scaleMin"          AS scale_min,
           d."scaleMax"          AS scale_max,
           d.decimals            AS decimals,
           d."unitLabel"         AS unit_label,
           (SELECT id FROM rel)          AS release_id,
           (SELECT release_key FROM rel) AS release_key,
           (SELECT captured_at FROM rel) AS captured_at,
           (SELECT zip FROM comp_fac)    AS competitor_zip,
           pm."valueNumeric"     AS p_value,
           pm."valueRaw"         AS p_raw,
           pm.suppressed         AS p_suppressed,
           pm."footnoteCodes"    AS p_footnotes,
           pm."periodStart"      AS p_period_start,
           pm."periodEnd"        AS p_period_end,
           cm."valueNumeric"     AS c_value,
           cm."valueRaw"         AS c_raw,
           cm.suppressed         AS c_suppressed,
           cm."footnoteCodes"    AS c_footnotes,
           cm."periodStart"      AS c_period_start,
           cm."periodEnd"        AS c_period_end
    FROM "CmsMeasureDefinition" d
    LEFT JOIN "CmsFacilityMeasure" pm
      ON pm.source = d.source
     AND pm."measureCode" = d."measureCode"
     AND pm."releaseId" = (SELECT id FROM rel)
     AND pm."facilityId" = (SELECT id FROM own_fac)
    LEFT JOIN "CmsFacilityMeasure" cm
      ON cm.source = d.source
     AND cm."measureCode" = d."measureCode"
     AND cm."releaseId" = (SELECT id FROM rel)
     AND cm."facilityId" = (SELECT id FROM comp_fac)
    WHERE d.source = ${source} AND d.surfaced = TRUE
    ORDER BY d."measureCode" ASC
  `;

  if (!rows.length) {
    return emptyDetail(CMS_COMPETITOR_DETAIL_STATUS.NO_QUALITY_DATA, market, null,
      'No CMS hospice quality measures are configured for display.');
  }

  // ---- round trip 11: the partner badge, through the shared rule ----------
  const partnerCcns = await verifiedPartnerCcns(prisma, source, [ccn]);

  const header = rows[0];
  const releaseId = header.release_id || null;

  // Deterministic display order: measureCode ascending, exactly as the Quality
  // service returns it. Nothing is reordered by which hospice looks better.
  const measures = rows.map((r) => {
    const direction = r.direction;
    const providerValue = publishedValue(r.p_value, r.p_suppressed);
    const competitorValue = publishedValue(r.c_value, r.c_suppressed);
    const comparison = compareValues(providerValue, competitorValue, direction);
    const periodStart = r.p_period_start || r.c_period_start || null;
    const periodEnd = r.p_period_end || r.c_period_end || null;
    return {
      measureCode: r.measure_code,
      displayName: r.short_label,
      cmsMeasureName: r.cms_measure_name,
      dimension: r.dimension,
      family: r.family,
      valueKind: r.value_kind,
      direction,
      // Presentation metadata, identical to what Quality Intelligence uses, so
      // the same value is formatted the same way in both modules.
      decimals: r.decimals,
      unitLabel: r.unit_label,
      scaleMin: r.scale_min === null || r.scale_min === undefined ? null : Number(r.scale_min),
      scaleMax: r.scale_max === null || r.scale_max === undefined ? null : Number(r.scale_max),
      period: periodStart || periodEnd
        ? { start: periodStart || null, end: periodEnd || null }
        : null,
      providerValue,
      providerValueRaw: r.p_raw === undefined ? null : r.p_raw,
      providerPublished: providerValue !== null,
      providerSuppressed: r.p_suppressed === true,
      providerFootnoteCodes: r.p_footnotes || [],
      competitorValue,
      competitorValueRaw: r.c_raw === undefined ? null : r.c_raw,
      competitorPublished: competitorValue !== null,
      competitorSuppressed: r.c_suppressed === true,
      competitorFootnoteCodes: r.c_footnotes || [],
      comparison,
      comparisonText: comparisonSentence(comparison, direction),
      // Surfaced so the UI never has to decide direction for itself.
      lowerIsBetter: direction === DIRECTION.LOWER_BETTER,
      directionNote: direction === DIRECTION.LOWER_BETTER ? LOWER_IS_BETTER_NOTE : null
    };
  });

  // Tallies of individual measures. Nothing is derived from them - no score, no
  // percentage, no index. The two identities below are asserted by the suite.
  const count = (v) => measures.filter((m) => m.comparison === v).length;
  const providerFavorableCount = count(COMPARISON.PROVIDER_HIGHER);
  const competitorFavorableCount = count(COMPARISON.COMPETITOR_HIGHER);
  const tiedCount = count(COMPARISON.SAME);
  const unavailableCount = count(COMPARISON.UNAVAILABLE);

  return {
    status: CMS_COMPETITOR_DETAIL_STATUS.RESOLVED,
    provider: { source, ccn: ownCcn, name: market.facility.name },
    competitor: {
      source,
      ccn,
      name: competitorEntry.name,
      city: competitorEntry.city,
      state: competitorEntry.state,
      officeZip: header.competitor_zip === undefined ? null : header.competitor_zip,
      bestHospicePartner: partnerCcns.has(ccn)
    },
    overlap: {
      sharedZipCount: competitorEntry.sharedZipCount,
      providerZipCount: competitorEntry.providerZipCount,
      competitorZipCount: competitorEntry.competitorZipCount,
      providerOverlapPct: competitorEntry.providerOverlapPct,
      competitorOverlapPct: competitorEntry.competitorOverlapPct,
      // The one place sharedZips is exposed. The landscape list deliberately
      // strips it; here exactly one competitor is in play, so it is a readable
      // list rather than thousands of strings nobody looks at.
      sharedZips: competitorEntry.sharedZips || []
    },
    comparisonSummary: {
      surfacedMeasureCount: measures.length,
      comparableMeasureCount: providerFavorableCount + competitorFavorableCount + tiedCount,
      providerFavorableCount,
      competitorFavorableCount,
      tiedCount,
      unavailableCount
    },
    measures,
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
  buildProviderCmsCompetitorDetail,
  CMS_COMPETITOR_DETAIL_STATUS,
  COMPARISON,
  CCN_PATTERN,
  DETAIL_SOURCE,
  LOWER_IS_BETTER_NOTE,
  METHODOLOGY,
  compareValues,
  comparisonSentence
};
