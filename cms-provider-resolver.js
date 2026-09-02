'use strict';
/**
 * Resolves the authoritative chain:
 *
 *   Provider -> ProviderExternalIdentity -> CmsFacility -> CmsFacilityServiceArea
 *
 * ProviderExternalIdentity is authoritative identity data. It means "this Best
 * Hospice provider IS this external provider". This resolver therefore only ever
 * resolves through a real, VERIFIED identity row. There is deliberately no
 * fallback of any kind - no provider-name match, no city/state match, no ZIP or
 * service-area inference, no nearest-facility guess, and no auto-creation of
 * identity rows. If the chain cannot be walked exactly, the resolver returns an
 * unresolved status and the caller shows nothing.
 *
 * Provider.internalRole has NO effect here. It governs public and business
 * isolation, not identity. An internal cms_reference account and a real customer
 * resolve through this identical path, and neither resolves without a verified
 * identity.
 */

// careType -> CMS source. Explicit and CLOSED: an unrecognised care type maps to
// null, never to a default.
//
// This is deliberately not server.js's normalizeCareType(), which falls back to
// 'hospice' for anything unknown. That fallback is correct for service-page
// routing and wrong here - it would claim Medicare publishes hospice data about
// a palliative or assisted-living provider.
//
// home-health is intentionally ABSENT. data/cms-dataset-registry.json maps the
// home-health family to cms_home_health and scripts/cms-archive.js archives it,
// but no ingester writes CmsFacility rows for that source yet, so there is
// nothing to resolve to. Adding it later is one line here plus one in
// IDENTIFIER_TYPE_BY_SOURCE - the resolver itself needs no redesign.
const CMS_SOURCE_BY_CARE_TYPE = Object.freeze({
  hospice: 'cms_hospice',
  'hospice-care': 'cms_hospice'
});

// Which identifier each source publishes. Mirrors sources[] in
// data/cms-dataset-registry.json; the two must stay in step.
const IDENTIFIER_TYPE_BY_SOURCE = Object.freeze({
  cms_hospice: 'ccn'
});

const CMS_RESOLVER_STATUS = Object.freeze({
  RESOLVED: 'resolved',
  PROVIDER_NOT_FOUND: 'provider_not_found',
  UNSUPPORTED_CARE_TYPE: 'unsupported_care_type',
  NO_VERIFIED_IDENTITY: 'no_verified_identity',
  MULTIPLE_VERIFIED_IDENTITIES: 'multiple_verified_identities',
  FACILITY_NOT_FOUND: 'facility_not_found'
});

function cmsSourceForCareType(careType) {
  const key = String(careType == null ? '' : careType).trim().toLowerCase();
  return Object.prototype.hasOwnProperty.call(CMS_SOURCE_BY_CARE_TYPE, key)
    ? CMS_SOURCE_BY_CARE_TYPE[key]
    : null;
}

// Explicit projections. Raw Prisma rows are never returned: Provider in
// particular carries email, Stripe ids, billing mode and subscription state,
// none of which belong in a CMS context response.
const publicProvider = (p) => ({
  id: p.id, name: p.name, careType: p.careType, city: p.city, state: p.state
});
const publicIdentity = (i) => ({
  source: i.source, identifierType: i.identifierType, externalId: i.externalId,
  verifiedAt: i.verifiedAt, confidence: i.confidence
});
const publicFacility = (f) => ({
  source: f.source, ccn: f.ccn, name: f.name, address: f.address, city: f.city,
  state: f.state, zip: f.zip, county: f.county, phone: f.phone,
  ownershipType: f.ownershipType, certificationDate: f.certificationDate
});
const publicRelease = (r) => (r ? { releaseKey: r.releaseKey, capturedAt: r.capturedAt } : null);

const unresolved = (status, provider, detail) => ({
  status,
  provider: provider ? publicProvider(provider) : null,
  identity: null,
  facility: null,
  serviceArea: null,
  freshness: null,
  detail
});

/**
 * @param prisma      a PrismaClient
 * @param providerId  the ONLY authoritative input. careType, CMS source, CCN and
 *                    facility are all derived from the database, never accepted
 *                    from a caller.
 */
async function resolveProviderCmsContext(prisma, providerId) {
  if (!providerId) {
    return unresolved(CMS_RESOLVER_STATUS.PROVIDER_NOT_FOUND, null, 'No provider id supplied.');
  }

  const provider = await prisma.provider.findUnique({
    where: { id: String(providerId) },
    select: { id: true, name: true, careType: true, city: true, state: true }
  });
  if (!provider) {
    return unresolved(CMS_RESOLVER_STATUS.PROVIDER_NOT_FOUND, null, 'No such provider.');
  }

  const source = cmsSourceForCareType(provider.careType);
  if (!source) {
    return unresolved(CMS_RESOLVER_STATUS.UNSUPPORTED_CARE_TYPE, provider,
      `No CMS dataset is resolved for care type "${provider.careType}".`);
  }
  const identifierType = IDENTIFIER_TYPE_BY_SOURCE[source];

  // Verified only. verifiedAt is the repo's acceptance marker: the identity
  // importer writes it from the human reviewer's reviewedAt, so a null means the
  // mapping was never accepted by a person.
  const identities = await prisma.providerExternalIdentity.findMany({
    where: { providerId: provider.id, source, identifierType, verifiedAt: { not: null } },
    orderBy: [{ externalId: 'asc' }],
    select: { source: true, identifierType: true, externalId: true, verifiedAt: true, confidence: true }
  });

  if (identities.length === 0) {
    return unresolved(CMS_RESOLVER_STATUS.NO_VERIFIED_IDENTITY, provider,
      `No verified ${source}/${identifierType} identity for this provider.`);
  }
  if (identities.length > 1) {
    // @@unique([source, externalId]) makes a CCN globally exclusive, but nothing
    // stops one provider holding several identities in the same source. Picking
    // one would silently attribute another organisation's CMS record, so this
    // fails closed and a human resolves the ambiguity.
    return unresolved(CMS_RESOLVER_STATUS.MULTIPLE_VERIFIED_IDENTITIES, provider,
      `${identities.length} verified ${source} identities exist for this provider; refusing to choose.`);
  }
  const identity = identities[0];

  // Source-consistent join. Both halves are required: (source, ccn) is the
  // natural key of CmsFacility, and a CCN alone is not unique across sources.
  const facility = await prisma.cmsFacility.findUnique({
    where: { source_ccn: { source: identity.source, ccn: identity.externalId } },
    include: { firstSeenRelease: true, lastSeenRelease: true }
  });
  if (!facility) {
    // A verified identity may legitimately outlive the ingested data: there is no
    // foreign key between the two precisely so acceptance does not depend on
    // ingestion. This is a staleness signal, not licence to guess.
    return unresolved(CMS_RESOLVER_STATUS.FACILITY_NOT_FOUND, provider,
      `No ingested ${identity.source} facility for ${identifierType} ${identity.externalId}.`);
  }

  // Through the relational key, scoped to the same source. @@unique([facilityId,
  // zip]) already guarantees one row per ZIP, so no application dedupe is needed.
  const serviceAreas = await prisma.cmsFacilityServiceArea.findMany({
    where: { facilityId: facility.id, source: facility.source },
    orderBy: [{ zip: 'asc' }],
    select: { zip: true }
  });

  // CmsFacility is CURRENT STATE, updated in place as CMS republishes, with
  // firstSeenRelease/lastSeenRelease bracketing observation. "Still current" is
  // therefore a comparison against the newest ingested release for the source,
  // not a stored flag.
  const latestRelease = await prisma.cmsRelease.findFirst({
    where: { source: facility.source },
    orderBy: { releaseKey: 'desc' }
  });

  return {
    status: CMS_RESOLVER_STATUS.RESOLVED,
    provider: publicProvider(provider),
    identity: publicIdentity(identity),
    facility: publicFacility(facility),
    serviceArea: { zipCount: serviceAreas.length, zips: serviceAreas.map((s) => s.zip) },
    freshness: {
      source: facility.source,
      firstSeen: publicRelease(facility.firstSeenRelease),
      lastSeen: publicRelease(facility.lastSeenRelease),
      latestIngestedRelease: publicRelease(latestRelease),
      currentInLatestRelease: !!latestRelease && facility.lastSeenReleaseId === latestRelease.id
    },
    detail: null
  };
}

module.exports = {
  resolveProviderCmsContext,
  cmsSourceForCareType,
  CMS_RESOLVER_STATUS,
  CMS_SOURCE_BY_CARE_TYPE,
  IDENTIFIER_TYPE_BY_SOURCE
};
