'use strict';
/**
 * CMS Roster & Facility Change derivation — "What's Changed", Phase 2B.
 *
 * WHAT THIS ANSWERS
 * "What changed across the Medicare-certified hospices in my market since the
 * previous CMS data release?"
 *
 * WHAT THIS IS NOT
 * It is NOT a feed of business events. Every finding here is a difference
 * between two CMS PUBLICATIONS. CMS does not send Best Hospice closure,
 * termination, enforcement or ownership-transaction data, and no dataset in
 * data/cms-dataset-registry.json carries any of it. So a facility that stops
 * appearing in the roster has not necessarily closed, and an ownership entry
 * that stops being published is a change in what CMS publishes rather than a
 * change of owner. The provider-facing wording in ROSTER_CHANGE_LABELS and
 * METHODOLOGY is written to survive that distinction, and the banned
 * vocabulary - closed, opened, acquired, sold, relocated, terminated - appears
 * nowhere in it.
 *
 * WHY IT READS OBSERVATIONS AND NOT CmsFacility
 * CmsFacility is current state: its ingest upsert overwrites name, address,
 * city, state, zip, county, phone, ownershipType and certificationDate in
 * place, so the previous release's values are gone. CmsFacilityObservation is
 * append-only, one row per facility per release, so every attribute delta here
 * is computed from two immutable snapshots. Nothing in this module reads a
 * descriptive column from CmsFacility.
 *
 * PRESENCE IS ROW EXISTENCE. A facility observed in a release has a row for
 * it; one absent from that release has none. That is what makes roster
 * membership answerable per release, and what makes a gap - present, absent,
 * present again - representable at all, which CmsFacility's single
 * firstSeen/lastSeen interval cannot express.
 *
 * DERIVED, NOT STORED. There is no change-event table and no migration. The
 * inputs are immutable, so the derivation is a pure function of them: it is
 * reproducible, it needs no rebuild path, and correcting a normalisation rule
 * corrects every past comparison at once. Persisting verdicts would freeze
 * judgements that are still deliberately provisional (see NORMALISATION).
 *
 * NORMALISATION IS FOR COMPARISON ONLY. Stored values stay exactly as CMS
 * published them and every event returns the raw FROM/TO. Normalisation exists
 * to suppress cosmetic noise, and it is deliberately shallow: case, whitespace
 * and the two punctuation marks CMS varies. There is NO fuzzy matching, no
 * Levenshtein, no abbreviation expansion, no corporate-suffix stripping and no
 * geocoding. Identity is never inferred from a name.
 *
 * Two suppressions are load-bearing rather than tidy, both measured on the
 * archived 2026-05-01 -> 2026-08-19 hospice releases:
 *   - COUNTY IS EXCLUDED FROM LOCATION ENTIRELY. CMS recased its county
 *     convention wholesale between those releases ("Maricopa" -> "MARICOPA"),
 *     which was 6,490 of 6,553 observed county differences. A county change
 *     with an unchanged address is a labelling change, not a location change,
 *     so county never triggers an event. It is counted in
 *     methodology.diagnostics only, as evidence the suppression is working.
 *   - OWNERSHIP IS CASE-FOLDED BEFORE COMPARISON. If CMS ever recases
 *     ownership the way it recased county, a case-sensitive comparison would
 *     manufacture thousands of ownership changes in a single release.
 *
 * OWNERSHIP NULLS ARE NOT CHANGES. In that same interval 788 of 1,310
 * ownership transitions were value -> null: CMS null ownership coverage went
 * from 11.16% to 23.39% of facilities, concentrated in a few states. Only 522
 * were value -> value. Folding the first group into "ownership changed" would
 * have overstated it by 2.5x, so value -> null and null -> value are reported
 * separately as publication-coverage observations and are NEVER counted in
 * summary.ownershipChanged.
 *
 * NO CERTIFICATION EVENT. certificationDate is stored on every observation but
 * is not a V1 event: it changed for zero of 6,610 shared facilities across the
 * measured interval. The field is available if a real change is ever seen.
 *
 * CMS `modified` IS NOT EVIDENCE OF CHANGE. The two archived releases carried
 * byte-identical zip.csv content while CMS advanced its `modified` date by
 * about four months. Nothing here consults `modified`, `capturedAt` or
 * `ingestedAt` to decide whether anything changed; those appear in the result
 * as release metadata only.
 *
 * NO PRIVATE DATA. Public CMS facts only. This module never reads Lead,
 * LeadNotification, LeadOutcome, referral, conversion or billing data, and it
 * never returns Best Hospice partner status. CMS market intelligence and
 * consumer lead routing remain separate domains: nothing here participates in
 * consumer lead eligibility.
 */
const { buildProviderCmsMarket, CMS_MARKET_STATUS, MARKET_SOURCE } = require('./cms-hospice-market');

/**
 * Inherits every upstream failure status verbatim so the strings cannot drift
 * from the resolver and market modules, and adds this module's own three.
 *
 * NOTE: CMS_MARKET_STATUS.RESOLVED is inherited but is never returned here -
 * success is OK, matching FUNNEL_STATUS.OK. `resolved` is mapped to OK once,
 * at the single point where the market result is consumed.
 */
const CMS_ROSTER_CHANGE_STATUS = Object.freeze({
  ...CMS_MARKET_STATUS,
  OK: 'ok',
  /// Fewer than two releases carry facility observations, so no comparison is
  /// possible. This is the honest state, not an error and not a set of zeroes.
  INSUFFICIENT_HISTORY: 'insufficient_history',
  /// No release carries facility observations at all.
  NO_OBSERVATIONS: 'no_observations'
});

/**
 * Provider-facing labels. Deliberately weaker than the plain-English reading of
 * the data, because the data cannot support the stronger claim. Reviewed
 * against the banned vocabulary in the module header.
 */
const ROSTER_CHANGE_LABELS = Object.freeze({
  rosterAdded: 'Newly present in CMS roster',
  rosterRemoved: 'Not present in latest CMS roster',
  nameChanged: 'CMS-published name changed',
  locationChanged: 'CMS-published address changed',
  ownershipChanged: 'CMS ownership classification changed',
  ownershipBecameUnpublished: 'CMS no longer publishes ownership for this facility',
  ownershipBecamePublished: 'CMS now publishes ownership for this facility'
});

const COVERAGE_DIRECTION = Object.freeze({
  BECAME_UNPUBLISHED: 'became_unpublished',
  BECAME_PUBLISHED: 'became_published'
});

const METHODOLOGY = Object.freeze({
  basis:
    'These are changes between two CMS data releases, not business events. Each finding is a '
    + 'difference between what CMS published in one release and what it published in the next.',
  rosterAbsence:
    'A facility absent from the latest CMS roster has not necessarily closed. Best Hospice '
    + 'receives no closure, termination or enforcement data from CMS, so absence from a '
    + 'published roster is an observation about the roster.',
  rosterPresence:
    'A facility newly present in the CMS roster may have been operating before CMS first '
    + 'published it. Newly present describes the roster, not the facility.',
  ownershipCoverage:
    'Ownership entries that stop being published are reported as a change in what CMS '
    + 'publishes, not as a change of ownership. The same applies in reverse when CMS begins '
    + 'publishing an ownership value it previously omitted.',
  comparisonScope:
    'Only facilities that share a CMS-reported service ZIP code with this provider are '
    + 'compared. Market membership uses current CMS service-area data.',
  identity:
    'Facilities are matched across releases by their CMS Certification Number. Names and '
    + 'addresses are never used to decide whether two records are the same facility.',
  normalisation:
    'Differences in capitalisation, spacing and the punctuation CMS varies are treated as the '
    + 'same value. County is not used to decide whether an address changed.',
  notIncluded:
    'Service-area ZIP coverage changes and quality-measure changes are not reported. CMS '
    + 'publishes quality measures for different measurement periods in different releases, so '
    + 'the two cannot be compared like for like.',
  freshness:
    'A change in the date CMS reports for a dataset is not evidence that its contents changed.'
});

// ---- normalisation --------------------------------------------------------
// Comparison-only. Every event returns the raw stored value.

/**
 * name / address / city. Exactly the documented steps, in order: string-coerce,
 * trim, drop the two punctuation marks CMS varies, collapse whitespace runs,
 * uppercase, and treat an emptied result as absent so "" and "." and null all
 * compare equal rather than registering as a change.
 */
const normText = (value) => {
  const s = String(value == null ? '' : value)
    .trim()
    .replace(/[.,]/g, '')
    .replace(/\s+/g, ' ')
    .trim()
    .toUpperCase();
  return s === '' ? null : s;
};

/** Two-letter code, already validated `^[A-Z]{2}$` at ingest. */
const normState = (value) => {
  const s = String(value == null ? '' : value).trim().toUpperCase();
  return s === '' ? null : s;
};

/**
 * Already sliced to 5 characters and validated `^\d{5}$` at ingest, and leading
 * zeros are significant, so this compares the stored value as-is.
 */
const normZip = (value) => {
  const s = String(value == null ? '' : value).trim();
  return s === '' ? null : s;
};

/**
 * Ownership. NULL STAYS NULL - it must remain distinguishable from every real
 * value, because that distinction is what separates a coverage change from an
 * ownership change. Case-folded for the reason given in the module header.
 */
const normOwnership = (value) => {
  if (value == null) return null;
  const s = String(value).trim().replace(/\s+/g, ' ').toUpperCase();
  return s === '' ? null : s;
};

/** County. Normalised for diagnostics only; never decides an event. */
const normCounty = (value) => normText(value);

// ---- empty result ---------------------------------------------------------
// Event arrays are always present and always arrays. An empty array means "no
// findings"; it never means "zero", and no count is ever presented as a finding.

const emptyEvents = () => ({
  rosterAdded: [],
  rosterRemoved: [],
  nameChanged: [],
  locationChanged: [],
  ownershipChanged: [],
  ownershipCoverageChanged: []
});

const emptySummary = () => ({
  rosterAdded: 0,
  rosterRemoved: 0,
  nameChanged: 0,
  locationChanged: 0,
  ownershipChanged: 0
});

const releaseMeta = (row) => (row
  ? { releaseKey: row.release_key, capturedAt: row.captured_at, ingestedAt: row.ingested_at }
  : null);

const emptyResult = (status, market, releases, detail) => ({
  status,
  provider: market && market.provider ? market.provider : null,
  facility: market && market.facility ? market.facility : null,
  releases: {
    latest: (releases && releases.latest) || null,
    previous: (releases && releases.previous) || null,
    releasesAvailable: (releases && releases.releasesAvailable) || 0
  },
  market: market && market.market
    ? {
      providerZipCount: market.market.providerZipCount,
      overlappingFacilityCount: market.market.overlappingFacilityCount
    }
    : null,
  summary: emptySummary(),
  events: emptyEvents(),
  methodology: METHODOLOGY,
  detail: detail == null ? null : detail
});

/**
 * @param prisma      a PrismaClient
 * @param providerId  the ONLY authoritative input. Care type, CMS source, CCN,
 *                    facility and market are all derived from the database, so
 *                    a caller cannot ask about a provider that is not theirs.
 */
async function buildProviderRosterChanges(prisma, providerId) {
  // ---- market: reuse, never reimplement --------------------------------
  // buildProviderCmsMarket is the single definition of a provider's CMS market,
  // already shared by Quality, Competitors and Competitor detail. It carries the
  // whole identity chain (Provider -> careType -> verified ProviderExternalIdentity
  // -> CmsFacility) and fails closed on every ambiguity, so every one of those
  // failure statuses is returned here unchanged rather than reinterpreted.
  const market = await buildProviderCmsMarket(prisma, providerId);
  if (market.status !== CMS_MARKET_STATUS.RESOLVED) {
    return emptyResult(market.status, market, null, market.detail);
  }

  const source = MARKET_SOURCE;

  // ---- release selection ------------------------------------------------
  // The two most recent releases THAT ACTUALLY CARRY OBSERVATIONS - not the two
  // most recent CmsRelease rows. A release can legitimately exist with zero
  // observations: releases ingested before the observation table existed have
  // none, and a future history-only backfill could add a release row without
  // them. Such a release must never become a comparison endpoint, or the
  // comparison would read every facility as newly present.
  //
  // Same EXISTS-guarded selection the quality module already uses to find the
  // newest release that has measurements.
  const releaseRows = await prisma.$queryRaw`
    SELECT r.id           AS id,
           r."releaseKey" AS release_key,
           r."capturedAt" AS captured_at,
           r."ingestedAt" AS ingested_at
    FROM "CmsRelease" r
    WHERE r.source = ${source}
      AND EXISTS (
        SELECT 1 FROM "CmsFacilityObservation" o
        WHERE o."releaseId" = r.id AND o.source = ${source})
    ORDER BY r."releaseKey" DESC
    LIMIT 2
  `;

  if (releaseRows.length === 0) {
    return emptyResult(CMS_ROSTER_CHANGE_STATUS.NO_OBSERVATIONS, market,
      { latest: null, previous: null, releasesAvailable: 0 },
      'No CMS hospice release carries facility observations yet.');
  }
  if (releaseRows.length === 1) {
    // The honest one-release state. Baseline metadata is reported so the caller
    // can say WHEN tracking started, and every event array stays empty.
    return emptyResult(CMS_ROSTER_CHANGE_STATUS.INSUFFICIENT_HISTORY, market,
      { latest: releaseMeta(releaseRows[0]), previous: null, releasesAvailable: 1 },
      'Only one CMS hospice release carries facility observations, so there is nothing to '
      + 'compare it against yet.');
  }

  const [latestRow, previousRow] = releaseRows;
  const releases = {
    latest: releaseMeta(latestRow),
    previous: releaseMeta(previousRow),
    releasesAvailable: releaseRows.length
  };

  // ---- market scoping ---------------------------------------------------
  // Compare only the facilities that share a service ZIP with this provider.
  // The provider's own facility is excluded by buildProviderCmsMarket and is
  // therefore out of scope for V1 - these are market events.
  //
  // sharedZipCount comes from the market builder, so no second overlap
  // calculation exists anywhere in this module.
  const overlapByCcn = new Map();
  (market.competitors || []).forEach((c) => {
    overlapByCcn.set(c.ccn, c.sharedZipCount);
  });
  const marketCcns = [...overlapByCcn.keys()];

  if (marketCcns.length === 0) {
    // A resolved provider with no overlapping facility. Not an error: there is
    // simply no market to report changes in.
    return emptyResult(CMS_ROSTER_CHANGE_STATUS.OK, market, releases,
      'No other Medicare-certified hospice shares a CMS-reported service ZIP code with this '
      + 'provider in the current CMS data.');
  }

  // ---- observation slices ----------------------------------------------
  // Every descriptive value is read from CmsFacilityObservation. No descriptive
  // column of CmsFacility is read anywhere in this module.
  const sliceFor = (releaseId) => prisma.$queryRaw`
    SELECT o.ccn                 AS ccn,
           o.name                AS name,
           o.address             AS address,
           o.city                AS city,
           o.state               AS state,
           o.zip                 AS zip,
           o.county              AS county,
           o."ownershipType"     AS ownership_type
    FROM "CmsFacilityObservation" o
    WHERE o.source = ${source}
      AND o."releaseId" = ${releaseId}
      AND o.ccn = ANY(${marketCcns})
  `;
  const [latestRows, previousRows] = await Promise.all([
    sliceFor(latestRow.id),
    sliceFor(previousRow.id)
  ]);

  // Keyed by CCN, which IS the canonical facility identity: CmsFacility carries
  // @@unique([source, ccn]), so within one source a CCN maps to exactly one
  // facility row, and the observation denormalises the CCN as published. Keying
  // by CCN is therefore equivalent to keying by facilityId, and it preserves the
  // identifier CMS actually printed. Nothing is matched by name or address.
  const byCcn = (rows) => {
    const m = new Map();
    rows.forEach((r) => m.set(r.ccn, r));
    return m;
  };
  const latest = byCcn(latestRows);
  const previous = byCcn(previousRows);

  // ---- comparison: a full outer join on canonical identity --------------
  const events = emptyEvents();
  let countyOnlyDifferences = 0;
  const allCcns = new Set([...latest.keys(), ...previous.keys()]);

  const ctx = (row) => ({ city: row.city, state: row.state });

  for (const ccn of allCcns) {
    const a = previous.get(ccn) || null;   // previous release
    const b = latest.get(ccn) || null;     // latest release
    const sharedZipCount = overlapByCcn.has(ccn) ? overlapByCcn.get(ccn) : null;

    if (a == null && b != null) {
      events.rosterAdded.push({
        ccn, name: b.name, city: b.city, state: b.state, sharedZipCount,
        label: ROSTER_CHANGE_LABELS.rosterAdded
      });
      continue;
    }
    if (a != null && b == null) {
      events.rosterRemoved.push({
        ccn, name: a.name, city: a.city, state: a.state, sharedZipCount,
        label: ROSTER_CHANGE_LABELS.rosterRemoved
      });
      continue;
    }
    if (a == null || b == null) continue;   // unreachable; keeps the branch total

    // --- name ---
    if (normText(a.name) !== normText(b.name)) {
      events.nameChanged.push({
        ccn, from: a.name, to: b.name, ...ctx(b), sharedZipCount,
        label: ROSTER_CHANGE_LABELS.nameChanged
      });
    }

    // --- location: address, city, state, zip. COUNTY IS NOT CONSULTED ---
    const locationDiffers = normText(a.address) !== normText(b.address)
      || normText(a.city) !== normText(b.city)
      || normState(a.state) !== normState(b.state)
      || normZip(a.zip) !== normZip(b.zip);
    if (locationDiffers) {
      events.locationChanged.push({
        ccn,
        name: b.name,
        from: { address: a.address, city: a.city, state: a.state, zip: a.zip },
        to: { address: b.address, city: b.city, state: b.state, zip: b.zip },
        sharedZipCount,
        label: ROSTER_CHANGE_LABELS.locationChanged
      });
    } else if (normCounty(a.county) !== normCounty(b.county)) {
      // County moved while the address did not. Counted as a diagnostic so the
      // suppression is visible and testable, and deliberately not an event.
      countyOnlyDifferences++;
    }

    // --- ownership: value -> value only ---
    const ownA = normOwnership(a.ownership_type);
    const ownB = normOwnership(b.ownership_type);
    if (ownA != null && ownB != null) {
      if (ownA !== ownB) {
        events.ownershipChanged.push({
          ccn, name: b.name, from: a.ownership_type, to: b.ownership_type, sharedZipCount,
          label: ROSTER_CHANGE_LABELS.ownershipChanged
        });
      }
    } else if (ownA != null && ownB == null) {
      events.ownershipCoverageChanged.push({
        ccn, name: b.name, direction: COVERAGE_DIRECTION.BECAME_UNPUBLISHED,
        label: ROSTER_CHANGE_LABELS.ownershipBecameUnpublished, sharedZipCount
      });
    } else if (ownA == null && ownB != null) {
      events.ownershipCoverageChanged.push({
        ccn, name: b.name, direction: COVERAGE_DIRECTION.BECAME_PUBLISHED,
        label: ROSTER_CHANGE_LABELS.ownershipBecamePublished, sharedZipCount
      });
    }
    // null -> null: no event of any kind.
  }

  // Deterministic ordering. sharedZipCount is an integer and is the primary
  // relevance signal, so ties are broken on CCN, which is unique within a
  // source - no two entries can ever compare equal.
  const order = (rows) => rows.sort((x, y) =>
    (y.sharedZipCount || 0) - (x.sharedZipCount || 0) || x.ccn.localeCompare(y.ccn));
  Object.keys(events).forEach((k) => order(events[k]));

  // summary counts the five CHANGE events only. ownershipCoverageChanged is
  // publication coverage, not a change, and is deliberately absent - folding it
  // into ownershipChanged would have overstated that count 2.5x on the measured
  // interval. There is also no "total changes" figure: the categories are not
  // commensurable, so a sum would have no defensible meaning.
  const summary = {
    rosterAdded: events.rosterAdded.length,
    rosterRemoved: events.rosterRemoved.length,
    nameChanged: events.nameChanged.length,
    locationChanged: events.locationChanged.length,
    ownershipChanged: events.ownershipChanged.length
  };

  return {
    status: CMS_ROSTER_CHANGE_STATUS.OK,
    provider: market.provider,
    facility: market.facility,
    releases,
    market: {
      providerZipCount: market.market.providerZipCount,
      overlappingFacilityCount: market.market.overlappingFacilityCount
    },
    summary,
    events,
    methodology: {
      ...METHODOLOGY,
      diagnostics: {
        facilitiesComparedInMarket: marketCcns.length,
        observedInPreviousRelease: previous.size,
        observedInLatestRelease: latest.size,
        /// County differences on facilities whose address did not change. Not a
        /// change event; reported so the county suppression stays visible.
        countyOnlyDifferences,
        ownershipCoverageChanged: events.ownershipCoverageChanged.length
      }
    },
    detail: null
  };
}

module.exports = {
  buildProviderRosterChanges,
  CMS_ROSTER_CHANGE_STATUS,
  ROSTER_CHANGE_LABELS,
  COVERAGE_DIRECTION,
  METHODOLOGY,
  // Exported for the test suite to exercise the suppression rules directly.
  normText,
  normState,
  normZip,
  normOwnership,
  normCounty
};
