'use strict';
/**
 * The Best Hospice partner badge rule, in one place.
 *
 * "Is this CMS facility the same organisation as a Best Hospice provider?" has
 * exactly one correct answer and one correct way to ask it. Every surface that
 * shows the badge resolves it through this module so the rule cannot drift into
 * two subtly different versions - the failure mode being a real hospice shown
 * our own internal reference record dressed up as a partner organisation.
 *
 * FOUR CONDITIONS, ALL IN SQL
 *   source            the CMS source the CCN belongs to. A CCN is not unique
 *                     across sources, so it is never matched on its own.
 *   identifierType    'ccn' - the identifier this source publishes.
 *   verifiedAt        NOT NULL. This is the repo's acceptance marker: the
 *                     identity importer writes it from the human reviewer's
 *                     reviewedAt, so a null means no person ever accepted the
 *                     mapping. An unverified or needs_research row never badges.
 *   internalRole      NULL only. An internal cms_reference account can hold a
 *                     perfectly valid verified identity - one does exist - and
 *                     badging it would attribute our test record to a real
 *                     hospice's competitor list.
 *
 * NO FUZZY MATCHING. Not by name, not by city, not by state, not by ZIP, not by
 * service-area overlap. Identity is the verified identity row or it is nothing.
 *
 * BOOLEAN ONLY. The projection is externalId and nothing else, so there is no
 * Provider id, email, phone, billing mode, subscription, plan tier or lead
 * setting in the result set to leak - not by mistake and not by a later edit
 * here. Callers get back a Set of CCNs and can answer only yes or no.
 *
 * Read-only. One bounded query regardless of how many CCNs are asked about;
 * @@unique([source, externalId]) makes each one an indexed lookup.
 */

// The identifier each CMS source publishes. Mirrors IDENTIFIER_TYPE_BY_SOURCE in
// cms-provider-resolver.js; the two must stay in step.
const IDENTIFIER_TYPE_BY_SOURCE = Object.freeze({ cms_hospice: 'ccn' });

/**
 * @param prisma  a PrismaClient
 * @param source  the CMS source, e.g. 'cms_hospice'
 * @param ccns    CCNs to check. Database-derived; never caller input.
 * @returns Set<string> of the CCNs that may show the badge. Never anything else.
 */
async function verifiedPartnerCcns(prisma, source, ccns) {
  const identifierType = IDENTIFIER_TYPE_BY_SOURCE[source];
  // An unmodelled source has no identifier we can match on, so nothing badges.
  // A correctness guard, not an optimisation: it fails closed rather than
  // falling back to a default identifier type.
  if (!identifierType) return new Set();
  const list = Array.isArray(ccns) ? ccns : [];

  // An EMPTY list is deliberately still queried. Short-circuiting it would be a
  // free saving, but it would also drop the competitor landscape from 11 bounded
  // round trips to 10 in the zero-overlap case, and this extraction is a
  // deduplication that must not move any measured behaviour. Worth revisiting on
  // its own terms.
  const rows = await prisma.providerExternalIdentity.findMany({
    where: {
      source,
      identifierType,
      externalId: { in: list },
      verifiedAt: { not: null },
      provider: { internalRole: null }
    },
    select: { externalId: true }
  });
  return new Set(rows.map((r) => r.externalId));
}

module.exports = { verifiedPartnerCcns, IDENTIFIER_TYPE_BY_SOURCE };
