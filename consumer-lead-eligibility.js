'use strict';
/**
 * The single definition of "may this provider receive a consumer's information".
 *
 * LEAF MODULE by design: zero requires, no database handle, no I/O. Every export
 * is pure, so the whole rule can be exercised without credentials.
 *
 * WHY THIS EXISTS
 * Three endpoints answered this question three different ways. /api/notify trusted
 * the browser's list of provider ids and never re-checked geography;
 * /api/job-notify did its own server-side matching; /api/discharge-referral ignored
 * serviceZipCodes entirely and fell back to EVERY public provider when geocoding
 * failed. ZIP lists were parsed three ways and the radius had three different
 * meanings. One canonical rule removes the drift.
 *
 * CARE TYPE IS DELIBERATELY NOT PART OF ELIGIBILITY.
 * Best Hospice intentionally routes a consumer care request to all otherwise
 * eligible nearby partners regardless of provider careType. Families often do not
 * know whether they need hospice, home health, home care or palliative support,
 * and nearby agencies are the ones best placed to assess and help them work it
 * out. The same reasoning currently applies to discharge referrals, where the
 * planner's selected care_type travels as CONTEXT in the notification rather than
 * as a filter. This module therefore takes no careType argument and never reads
 * one - a future product decision to filter would be a deliberate change here,
 * not an accident somewhere else.
 *
 * CMS DATA NEVER GRANTS ELIGIBILITY.
 * CmsFacilityServiceArea says "Medicare reports this certified hospice serves this
 * ZIP". That is market intelligence. It is NOT "this provider agreed to receive
 * Best Hospice consumer opportunities here". The two must never be conflated, so
 * no Cms* table is referenced here, or reachable from here.
 */

// The consumer search radius, and the hard ceiling for any provider's own radius.
// Mirrors the value search-results.js uses when matching in the browser.
const CONSUMER_LEAD_RADIUS_KM = 96.6;

/**
 * Flags half of the rule, as a Prisma `where` fragment.
 *
 * Written in POSITIVE form on purpose. The previous /api/notify implementation
 * built a blocklist of ineligible ids and notified everything else, so any column
 * that failed to disqualify a provider silently let them through. An allowlist
 * fails closed instead.
 *
 * The billing clause reproduces the pre-existing rule EXACTLY - excluded when
 * billingMode is 'off', and when billingMode is 'billed' without a current Stripe
 * status. 'free' (the schema default) is eligible, and so is any other mode, which
 * is the behaviour that was already shipped; this module preserves it rather than
 * quietly tightening it.
 *
 * `internalRole: null` is the same fragment as server.js PUBLIC_PROVIDER_WHERE and
 * is listed first for the same reason it always has been: an internal account must
 * stay excluded even if receiveClientLeads is later flipped back to true by hand.
 */
const CONSUMER_LEAD_ELIGIBLE_WHERE = Object.freeze({
  internalRole: null,
  receiveClientLeads: true,
  OR: [
    { billingMode: 'billed', subscriptionStatus: { in: ['active', 'trialing'] } },
    { billingMode: { notIn: ['off', 'billed'] } }
  ]
});

/**
 * The canonical ZIP-list parser. Accepts every separator a provider might type -
 * commas, spaces, semicolons, tabs, newlines - and keeps only well-formed 5-digit
 * ZIPs. server.js previously split on ',' alone in one place and not at all in
 * another, so a provider using newlines was matched inconsistently.
 */
function parseServiceZipCodes(value) {
  return String(value == null ? '' : value)
    .split(/[\s,;\n\r\t]+/)
    .map((z) => z.trim())
    .filter((z) => /^\d{5}$/.test(z));
}

// Self-contained so this stays a leaf module. Identical formula to server.js's
// haversineKm; a test asserts the two agree.
function haversineKm(lat1, lon1, lat2, lon2) {
  const toRad = (v) => (v * Math.PI) / 180;
  const R = 6371;
  const dLat = toRad(lat2 - lat1);
  const dLon = toRad(lon2 - lon1);
  const a = Math.sin(dLat / 2) ** 2
    + Math.cos(toRad(lat1)) * Math.cos(toRad(lat2)) * Math.sin(dLon / 2) ** 2;
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
}

/**
 * Geography half of the rule. `location` is { zip, lat, lon }; lat/lon may be null
 * when geocoding failed.
 *
 * A CONFIGURED ZIP LIST IS EXCLUSIVE. If a provider has listed ZIPs, those are the
 * only places they receive leads, and their radius is ignored entirely. This is
 * what the browser and /api/job-notify already did, and it is the behaviour
 * /api/discharge-referral was missing: two real providers with explicit ZIP lists
 * and serviceRadiusKm = 0 were being given a 96.6 km radius there, reaching ZIPs
 * they had deliberately left out.
 *
 * FAILS CLOSED. No usable coordinates means a radius-mode provider does not cover
 * the location, full stop. A geocode failure must never widen the eligible set -
 * the caller routes the family into New Territory Outreach instead.
 */
function providerCoversLocation(provider, location) {
  if (!provider || !location) return false;

  const zips = parseServiceZipCodes(provider.serviceZipCodes);
  if (zips.length) {
    const zip = String(location.zip == null ? '' : location.zip).trim();
    return /^\d{5}$/.test(zip) && zips.includes(zip);
  }

  const lat = Number(location.lat);
  const lon = Number(location.lon);
  if (!Number.isFinite(lat) || !Number.isFinite(lon)) return false;
  const pLat = Number(provider.lat);
  const pLon = Number(provider.lon);
  if (!Number.isFinite(pLat) || !Number.isFinite(pLon)) return false;

  // A missing or non-positive radius means "use the standard consumer radius",
  // matching the browser's `provider.serviceRadiusKm || searchRadiusKm`. The
  // provider's own radius can narrow the match but never widen it past the
  // consumer search radius.
  const own = Number(provider.serviceRadiusKm);
  const providerRadius = Number.isFinite(own) && own > 0 ? own : CONSUMER_LEAD_RADIUS_KM;
  const radius = Math.min(CONSUMER_LEAD_RADIUS_KM, providerRadius);
  return haversineKm(lat, lon, pLat, pLon) <= radius;
}

/** True when `provider` may receive this consumer's information. */
function isProviderEligibleForConsumerLead(provider, location) {
  if (!provider) return false;
  if (provider.internalRole != null) return false;
  if (provider.receiveClientLeads !== true) return false;
  if (!isBillingEligible(provider)) return false;
  return providerCoversLocation(provider, location);
}

/**
 * The in-memory twin of the billing clause in CONSUMER_LEAD_ELIGIBLE_WHERE, for
 * callers that already hold a provider row. A test asserts the two agree over
 * every mode/status combination.
 */
function isBillingEligible(provider) {
  const mode = String(provider && provider.billingMode);
  if (mode === 'off') return false;
  if (mode === 'billed') {
    const status = String(provider.subscriptionStatus == null ? '' : provider.subscriptionStatus);
    return status === 'active' || status === 'trialing';
  }
  return true;
}

module.exports = {
  CONSUMER_LEAD_RADIUS_KM,
  CONSUMER_LEAD_ELIGIBLE_WHERE,
  parseServiceZipCodes,
  providerCoversLocation,
  isBillingEligible,
  isProviderEligibleForConsumerLead
};
