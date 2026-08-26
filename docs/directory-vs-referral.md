# Public directory vs. referral distribution

These two systems behave differently **on purpose**. If you are reading this
because a home-care provider received a hospice inquiry, that is not a bug.

## Public directory — service-specific

`/hospice-care/<place>`, `/palliative-care/<place>` and `/home-care/<place>`
list only providers whose `Provider.careType` matches that service.

Why: a family researching hospice must not be shown a non-medical home-care
agency presented as a hospice. That is inaccurate for the family and, at scale,
tells search engines the pages are interchangeable. Enforced in
`providersByLocation()` and in the state/hub route queries. Anything that
derives from those arrays — visible listings, provider counts, conditional
titles and descriptions, JSON-LD — inherits the filter automatically.

Regression coverage: `scripts/test-service-routing.js`.

## Referral distribution — deliberately cross-service

`/api/notify` does **not** filter candidate providers by care type. A family
inquiry may reach nearby participating providers across hospice, home care and
other senior-care categories.

Why (product decision, Crawford, 2026-08-25): families frequently do not know
which level of care they need. Someone asking for home care may actually need
hospice; someone asking for hospice may not yet qualify and may need home care.
Allowing broader outreach lets a provider talk to the family and help them find
the right level of care.

**Do not add care-type filtering to `/api/notify` without approval, and do not
make the public directory cross-service just because distribution is.**

## The consequence to keep honest

Because distribution is broader than the directory, family-facing copy must not
promise that an inquiry goes only to the care type the family selected. The
search funnel asks "What type of care?" — that answer is context for providers,
not a routing filter. Any wording implying otherwise should be corrected.
