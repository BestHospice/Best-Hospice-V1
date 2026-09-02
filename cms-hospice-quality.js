'use strict';
/**
 * Quality Intelligence V1 — CMS hospice quality, benchmarked against the
 * hospices that actually overlap the provider's service area.
 *
 * THE QUESTION THIS ANSWERS
 * "How does my hospice's CMS-measured quality compare with the hospices that
 * actually overlap my service area?" Not "what does CMS publish about me" - that
 * would be a data dump. Every measure is returned with its peer median, its
 * comparable peer count and a direction-aware verdict.
 *
 * PEER DEFINITION — REUSED, NOT REDEFINED
 * A market peer is another CMS hospice sharing at least one CMS-reported service
 * ZIP code with the provider. That is My Market's definition, and this module
 * gets the peer set by CALLING buildProviderCmsMarket() rather than by
 * reimplementing the overlap query. There is therefore exactly one market
 * definition in the codebase, and identity still resolves through
 * cms-provider-resolver.js (transitively, via the market module) with no second
 * identity path and no fuzzy fallback.
 *
 * DIRECTIONALITY IS NEVER INFERRED HERE
 * Whether a higher or a lower published value is better care is read from
 * CmsMeasureDefinition.direction, which the ingester seeds from
 * data/cms-hospice-quality-measures.json, which in turn cites CMS documentation.
 * Nothing in this file decides direction from a measure code, a measure name, or
 * the shape of the data.
 *
 * CMS's own H_012_xx_PERCENTILE fields are NOT used and must never be surfaced.
 * They are monotone ranks of the RAW value with no directional correction
 * (Spearman rho = 1.0000 against the observed value on all ten HCI indicators),
 * so on a lower-is-better indicator a higher CMS percentile means WORSE care.
 * Every percentage and count in this module is computed from the provider's own
 * overlapping-hospice peer set instead.
 *
 * SUPPRESSED DATA IS NOT ZERO
 * A measure CMS withheld is excluded from every peer denominator, is never
 * imputed, is never ranked, and produces verdict "not_published". A measure with
 * fewer than MIN_COMPARABLE_PEERS comparable peers produces
 * "insufficient_peers": the provider's own CMS value is still returned, but every
 * comparative field is null.
 *
 * WHAT THIS IS NOT
 * There is no proprietary Best Hospice composite quality score. Nothing here
 * implies market share, patient volume, referral volume or causation, and nothing
 * consults Best Hospice subscription, billing or lead data.
 */
const { buildProviderCmsMarket, CMS_MARKET_STATUS } = require('./cms-hospice-market');
const MEASURE_REGISTRY = require('./data/cms-hospice-quality-measures.json');

const QUALITY_SOURCE = 'cms_hospice';

// A hard floor, not a preference. Editing the registry cannot lower it, because
// a "median" of three hospices is not a market benchmark and a count-based claim
// over a handful of peers identifies them.
const MIN_COMPARABLE_PEERS_FLOOR = 5;
const MIN_COMPARABLE_PEERS = Math.max(
  MIN_COMPARABLE_PEERS_FLOOR,
  Number(MEASURE_REGISTRY.minimumComparablePeers) || 0);

const CMS_QUALITY_STATUS = Object.freeze({
  ...CMS_MARKET_STATUS,
  NO_QUALITY_DATA: 'no_quality_data'
});

// verdict values.
//
// IMPORTANT: above_peer_median / below_peer_median / at_peer_median describe the
// POSITION of the provider's published value relative to the peer median,
// numerically. They do NOT mean "better" or "worse" - for a lower-is-better
// measure such as early live discharges, below_peer_median is the GOOD outcome.
// Direction-aware evaluation is carried separately on `favorable`, and callers
// must use that for any language or styling that implies quality.
const VERDICT = Object.freeze({
  ABOVE: 'above_peer_median',
  BELOW: 'below_peer_median',
  AT: 'at_peer_median',
  INSUFFICIENT_PEERS: 'insufficient_peers',
  NOT_PUBLISHED: 'not_published'
});

const DIRECTION = Object.freeze({ HIGHER_BETTER: 'higher_better', LOWER_BETTER: 'lower_better' });

// The one exact sentence for a hospice CMS has published no survey result for.
// Kept here so the API and the UI cannot drift into two different wordings.
const CAHPS_UNPUBLISHED_MESSAGE =
  'CMS has not published a family caregiver survey result for this hospice.';

const round2 = (v) => (typeof v === 'number' && Number.isFinite(v) ? Math.round(v * 100) / 100 : null);

// Presentation-only grouping metadata. Measure SEMANTICS (direction, labels,
// scale) come from the database, because those are the values that were actually
// validated against CMS's own measure names at ingestion time. Dimension labels
// carry no semantics, so reading them from the tracked registry is safe.
const DIMENSION_META = new Map(
  (MEASURE_REGISTRY.dimensions || []).map((d) => [d.key, d]));

const emptyQuality = (status, market, detail) => ({
  status,
  provider: (market && market.provider) || null,
  facility: (market && market.facility) || null,
  summary: null,
  dimensions: null,
  measures: null,
  strengths: null,
  areasToReview: null,
  peerContext: null,
  freshness: (market && market.freshness) || null,
  methodology: null,
  detail
});

const METHODOLOGY = Object.freeze({
  peerDefinition:
    "Comparisons are calculated by Best Hospice from CMS-published measures across hospices sharing this provider's "
    + 'CMS-reported service ZIP codes.',
  minimumComparablePeers: MIN_COMPARABLE_PEERS,
  suppression:
    'Measures CMS did not publish for a hospice are excluded from every comparison. They are never treated as zero, '
    + 'averaged in, or estimated.',
  notRepresenting: Object.freeze([
    'market share',
    'patient volume',
    'referral relationships',
    'causation',
    'a proprietary Best Hospice quality rating'
  ]),
  cmsPercentileExcluded:
    "CMS's own published percentile fields rank the raw measure value and carry no correction for whether a higher or "
    + 'lower value is better, so they are not used as a quality rank.'
});

/**
 * @param prisma      a PrismaClient
 * @param providerId  the ONLY authoritative input. Care type, CMS source, CCN,
 *                    facility, service area and peer set are all derived from
 *                    the database.
 */
async function buildProviderCmsQuality(prisma, providerId) {
  // Round trips 1-9. Also the single identity path: this resolves the provider
  // through cms-provider-resolver.js and fails closed on every unresolved state.
  const market = await buildProviderCmsMarket(prisma, providerId);
  if (market.status !== CMS_MARKET_STATUS.RESOLVED) {
    return emptyQuality(market.status, market, market.detail);
  }
  if (market.facility.source !== QUALITY_SOURCE) {
    return emptyQuality(CMS_QUALITY_STATUS.MARKET_UNAVAILABLE, market,
      `Quality intelligence is not implemented for source "${market.facility.source}".`);
  }

  const source = market.facility.source;
  const ownCcn = market.facility.ccn;
  const peerCcns = market.competitors.map((c) => c.ccn);

  // Round trip 10. The newest release that actually HAS measurements, which is
  // not necessarily the newest release overall: the facility roster and the
  // quality files are ingested by separate authorized steps, so quality can
  // legitimately lag by one release. Reading the newest release unconditionally
  // would show an empty report instead of the most recent real data.
  const [qualityRelease] = await prisma.$queryRaw`
    SELECT r.id AS id, r."releaseKey" AS release_key, r."capturedAt" AS captured_at
    FROM "CmsRelease" r
    WHERE r.source = ${source}
      AND EXISTS (
        SELECT 1 FROM "CmsFacilityMeasure" m
        WHERE m."releaseId" = r.id AND m.source = ${source})
    ORDER BY r."releaseKey" DESC
    LIMIT 1
  `;
  if (!qualityRelease) {
    return emptyQuality(CMS_QUALITY_STATUS.NO_QUALITY_DATA, market,
      'No CMS hospice quality release has been ingested yet.');
  }
  const releaseId = qualityRelease.id;

  // Round trip 11. Every SURFACED measure definition, LEFT JOINed to this
  // provider's own measurement. LEFT so a measure CMS published nothing for
  // still comes back, as a definition with no value, rather than vanishing.
  const ownRows = await prisma.$queryRaw`
    SELECT d."measureCode"     AS measure_code,
           d."cmsMeasureName"  AS cms_measure_name,
           d."shortLabel"      AS short_label,
           d.dimension         AS dimension,
           d.family            AS family,
           d."valueKind"       AS value_kind,
           d.direction         AS direction,
           d."scaleMin"        AS scale_min,
           d."scaleMax"        AS scale_max,
           d.decimals          AS decimals,
           d."unitLabel"       AS unit_label,
           m."valueNumeric"    AS value_numeric,
           m."valueRaw"        AS value_raw,
           m.suppressed        AS suppressed,
           m."footnoteCodes"   AS footnote_codes,
           m.denominator       AS denominator,
           m."starRating"      AS star_rating,
           m."periodStart"     AS period_start,
           m."periodEnd"       AS period_end
    FROM "CmsMeasureDefinition" d
    LEFT JOIN "CmsFacility" own
      ON own.source = d.source AND own.ccn = ${ownCcn}
    LEFT JOIN "CmsFacilityMeasure" m
      ON m.source = d.source
     AND m."measureCode" = d."measureCode"
     AND m."releaseId" = ${releaseId}
     AND m."facilityId" = own.id
    WHERE d.source = ${source} AND d.surfaced = TRUE
    ORDER BY d."measureCode" ASC
  `;
  if (!ownRows.length) {
    return emptyQuality(CMS_QUALITY_STATUS.NO_QUALITY_DATA, market,
      'No CMS hospice quality measures are configured for display.');
  }

  // Round trip 12. Peer aggregates for EVERY measure in ONE set-based query.
  // Grouped in PostgreSQL, so the cost does not grow with the number of
  // overlapping hospices and no query is ever issued per peer or per measure.
  //
  // Only rows where CMS published a comparable observation take part:
  // suppressed = false AND valueNumeric IS NOT NULL. That is what keeps a
  // withheld measure out of the denominator instead of counting as a zero.
  //
  // The provider's own facility is excluded explicitly as well as by
  // construction (My Market never returns it as a competitor), so a future
  // change to the peer list cannot silently make a hospice its own benchmark.
  const peerRows = await prisma.$queryRaw`
    WITH own_facility AS (
      SELECT id FROM "CmsFacility" WHERE source = ${source} AND ccn = ${ownCcn}
    ),
    own_obs AS (
      SELECT m."measureCode" AS code, m."valueNumeric" AS v
      FROM "CmsFacilityMeasure" m
      JOIN own_facility o ON o.id = m."facilityId"
      WHERE m.source = ${source} AND m."releaseId" = ${releaseId}
        AND m.suppressed = FALSE AND m."valueNumeric" IS NOT NULL
    ),
    peer_facility AS (
      SELECT f.id
      FROM "CmsFacility" f
      WHERE f.source = ${source}
        AND f.ccn = ANY(${peerCcns}::text[])
        AND f.ccn <> ${ownCcn}
    ),
    peer_obs AS (
      SELECT m."measureCode" AS code, m."valueNumeric" AS v
      FROM "CmsFacilityMeasure" m
      JOIN peer_facility p ON p.id = m."facilityId"
      WHERE m.source = ${source} AND m."releaseId" = ${releaseId}
        AND m.suppressed = FALSE AND m."valueNumeric" IS NOT NULL
    )
    SELECT o.code                                                        AS measure_code,
           count(*)::int                                                 AS comparable_count,
           percentile_cont(0.5) WITHIN GROUP (ORDER BY p.v)               AS peer_median,
           min(p.v)                                                      AS peer_min,
           max(p.v)                                                      AS peer_max,
           count(*) FILTER (WHERE p.v < o.v)::int                         AS peers_lower,
           count(*) FILTER (WHERE p.v > o.v)::int                         AS peers_higher,
           count(*) FILTER (WHERE p.v = o.v)::int                         AS peers_equal
    FROM own_obs o
    JOIN peer_obs p ON p.code = o.code
    GROUP BY o.code, o.v
  `;
  const peerByCode = new Map(peerRows.map((r) => [r.measure_code, r]));

  const measures = ownRows.map((r) => {
    const decimals = Number(r.decimals);
    const direction = r.direction;
    const published = r.value_numeric !== null && r.value_numeric !== undefined && r.suppressed === false;
    const value = published ? Number(r.value_numeric) : null;

    const base = {
      measureCode: r.measure_code,
      cmsMeasureName: r.cms_measure_name,
      shortLabel: r.short_label,
      dimension: r.dimension,
      family: r.family,
      valueKind: r.value_kind,
      direction,
      decimals,
      unitLabel: r.unit_label,
      scaleMin: r.scale_min === null ? null : Number(r.scale_min),
      scaleMax: r.scale_max === null ? null : Number(r.scale_max),
      period: r.period_start && r.period_end
        // @db.Date round-trips as a Date at UTC midnight; slice the ISO form so a
        // calendar date stays a calendar date and never shifts a day westward.
        ? { start: new Date(r.period_start).toISOString().slice(0, 10),
            end: new Date(r.period_end).toISOString().slice(0, 10) }
        : null,
      provider: {
        value,
        // The CMS cell verbatim, including "Not Available", so the API never has
        // to invent a placeholder and the UI never has to guess why.
        valueRaw: r.value_raw === null || r.value_raw === undefined ? null : String(r.value_raw),
        published,
        suppressed: r.suppressed === true,
        denominator: r.denominator === null || r.denominator === undefined ? null : Number(r.denominator),
        starRating: r.star_rating === null || r.star_rating === undefined ? null : Number(r.star_rating),
        footnoteCodes: Array.isArray(r.footnote_codes) ? r.footnote_codes : []
      },
      peers: null,
      verdict: VERDICT.NOT_PUBLISHED,
      favorable: null,
      favorablePeerCount: null,
      differenceFromPeerMedian: null,
      comparisonAllowed: false
    };

    if (!published) return base;

    const agg = peerByCode.get(r.measure_code);
    const comparableCount = agg ? Number(agg.comparable_count) : 0;
    const peersLower = agg ? Number(agg.peers_lower) : 0;
    const peersHigher = agg ? Number(agg.peers_higher) : 0;
    const peersEqual = agg ? Number(agg.peers_equal) : 0;
    const median = agg && agg.peer_median !== null ? Number(agg.peer_median) : null;

    if (comparableCount < MIN_COMPARABLE_PEERS || median === null) {
      // Below the threshold the response carries the peer COUNT and nothing else.
      // The median, range and directional counts are withheld rather than merely
      // flagged, because anything a caller can read it can render - and a median
      // over four hospices is both an unreliable benchmark and close to naming
      // them. The provider's own CMS value is still returned above.
      base.peers = {
        comparableCount,
        median: null, min: null, max: null,
        lowerThanProvider: null, higherThanProvider: null, equalToProvider: null
      };
      base.verdict = VERDICT.INSUFFICIENT_PEERS;
      return base;
    }

    base.peers = {
      comparableCount,
      median: round2(median),
      min: round2(Number(agg.peer_min)),
      max: round2(Number(agg.peer_max)),
      lowerThanProvider: peersLower,
      higherThanProvider: peersHigher,
      equalToProvider: peersEqual
    };
    base.comparisonAllowed = true;
    base.verdict = value > median ? VERDICT.ABOVE : value < median ? VERDICT.BELOW : VERDICT.AT;
    // Direction-aware, and the ONLY field that means "better". For a
    // lower-is-better measure the favourable peers are the ones ABOVE us.
    if (value === median) {
      base.favorable = null;
      base.favorablePeerCount = direction === DIRECTION.LOWER_BETTER ? peersHigher : peersLower;
    } else if (direction === DIRECTION.LOWER_BETTER) {
      base.favorable = value < median;
      base.favorablePeerCount = peersHigher;
    } else {
      base.favorable = value > median;
      base.favorablePeerCount = peersLower;
    }
    base.differenceFromPeerMedian = round2(value - median);
    return base;
  });

  const byCode = new Map(measures.map((m) => [m.measureCode, m]));
  const publishedMeasures = measures.filter((m) => m.provider.published);
  const comparedMeasures = measures.filter((m) => m.comparisonAllowed);

  // Nothing usable at all. Fail closed rather than return an expandable report
  // that pretends data exists.
  if (!publishedMeasures.length) {
    return emptyQuality(CMS_QUALITY_STATUS.NO_QUALITY_DATA, market,
      'CMS has not published any of the quality measures we report for this hospice.');
  }

  // Grouped for display, in the registry's declared order. A dimension whose
  // measures CMS published nothing for is still returned, carrying an explicit
  // message, so the UI shows a reason instead of an empty row or a zero.
  const dimKeys = [...new Set(measures.map((m) => m.dimension))];
  dimKeys.sort((a, b) => {
    const oa = DIMENSION_META.has(a) ? Number(DIMENSION_META.get(a).order) : Number.MAX_SAFE_INTEGER;
    const ob = DIMENSION_META.has(b) ? Number(DIMENSION_META.get(b).order) : Number.MAX_SAFE_INTEGER;
    return oa - ob || a.localeCompare(b);
  });
  const dimensions = dimKeys.map((key) => {
    const meta = DIMENSION_META.get(key) || {};
    const codes = measures.filter((m) => m.dimension === key).map((m) => m.measureCode);
    const anyPublished = codes.some((c) => byCode.get(c).provider.published);
    const conditional = meta.conditional === true;
    return {
      key,
      label: meta.label || key,
      blurb: meta.blurb || null,
      conditional,
      measureCodes: codes,
      anyPublished,
      // A conditional dimension gets the one agreed sentence; a core dimension
      // gets a neutral one. Neither is a zero and neither is blank.
      message: anyPublished
        ? null
        : (conditional
          ? CAHPS_UNPUBLISHED_MESSAGE
          : 'CMS has not published this measure for this hospice.')
    };
  });

  // Strongest and weakest, direction-aware and comparison-gated. Ranked by how
  // far from the peer median the provider sits, normalised by the measure's own
  // scale so a 0-10 index and a 0-100 percentage are ranked on comparable terms.
  const spread = (m) => {
    const lo = m.scaleMin, hi = m.scaleMax;
    const range = typeof lo === 'number' && typeof hi === 'number' && hi > lo ? hi - lo : 100;
    return Math.abs(m.differenceFromPeerMedian || 0) / range;
  };
  const rank = (list) => list
    .slice()
    .sort((a, b) => spread(b) - spread(a)
      || a.shortLabel.localeCompare(b.shortLabel)
      || a.measureCode.localeCompare(b.measureCode))
    .map((m) => m.measureCode);
  const strengths = rank(comparedMeasures.filter((m) => m.favorable === true));
  const areasToReview = rank(comparedMeasures.filter((m) => m.favorable === false));

  const careIndexMeasure = measures.find((m) => m.dimension === 'careIndex' && m.provider.published) || null;
  const favorableCount = comparedMeasures.filter((m) => m.favorable === true).length;
  const unfavorableCount = comparedMeasures.filter((m) => m.favorable === false).length;

  return {
    status: CMS_QUALITY_STATUS.RESOLVED,
    provider: market.provider,
    facility: market.facility,
    summary: {
      // Real CMS values only. Null when CMS published nothing, so the collapsed
      // card has to say so rather than render a fabricated headline number.
      careIndex: careIndexMeasure
        ? {
            measureCode: careIndexMeasure.measureCode,
            value: careIndexMeasure.provider.value,
            scaleMax: careIndexMeasure.scaleMax,
            unitLabel: careIndexMeasure.unitLabel,
            comparisonAllowed: careIndexMeasure.comparisonAllowed
          }
        : null,
      surfacedMeasureCount: measures.length,
      publishedMeasureCount: publishedMeasures.length,
      comparedMeasureCount: comparedMeasures.length,
      favorableCount,
      unfavorableCount
    },
    dimensions,
    measures,
    strengths,
    areasToReview,
    peerContext: {
      // Restated from My Market's own output so the provider can see the
      // comparison is drawn from exactly the market they were already shown.
      definition: 'Another CMS-certified hospice that serves at least one of your CMS-reported service ZIP codes.',
      providerZipCount: market.market.providerZipCount,
      overlappingFacilityCount: market.market.overlappingFacilityCount,
      minimumComparablePeers: MIN_COMPARABLE_PEERS
    },
    freshness: {
      ...market.freshness,
      qualityRelease: {
        releaseKey: qualityRelease.release_key,
        capturedAt: qualityRelease.captured_at
      }
    },
    methodology: METHODOLOGY,
    detail: null
  };
}

module.exports = {
  buildProviderCmsQuality,
  CMS_QUALITY_STATUS,
  QUALITY_SOURCE,
  VERDICT,
  DIRECTION,
  MIN_COMPARABLE_PEERS,
  CAHPS_UNPUBLISHED_MESSAGE,
  METHODOLOGY
};
