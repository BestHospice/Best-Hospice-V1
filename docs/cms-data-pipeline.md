# CMS data pipeline

How Best Hospice preserves CMS Provider Data Catalog history, and how that
history relates to our own Provider records.

**Implemented today: archival and schema-drift detection only.** Nothing in this
pipeline writes to the database. There is no CMS ingestion into Postgres yet.

---

## Why archive at all

CMS overwrites its Provider Data Catalog files **in place**. There is no official
archive of prior releases. Any question of the form "how did this change?" can
only ever be answered from snapshots we captured at the time, and a missed
release is unrecoverable.

This is not hypothetical. Between the `2026-05-01` and `2026-08-19` hospice
releases the national hospice count moved 6,852 → 6,669. Which organisations
left, and which entered, is visible only because both snapshots exist.

Cost is about 5 MB gzipped per hospice release and about 3 MB per home-health
release.

---

## Sources

Two independent source families, archived separately:

| archive family | identity source | identifier | datasets |
| --- | --- | --- | --- |
| `hospice` | `cms_hospice` | CCN | 6, all required |
| `home-health` | `cms_home_health` | CCN | 5, all required |

### These are two separate namespaces

**Archive family** (`hospice`, `home-health`) names a set of CMS datasets. It is
used by `--source`, the release directory, `manifest.source`, the registry
`source` field and the workflow matrix.

**Identity source** (`cms_hospice`, `cms_home_health`) is the value stored in
`ProviderExternalIdentity.source`. It is used by the identity decision artifact,
the validator and the importer.

They are deliberately different strings and **must never be joined by string
equality**. The only sanctioned mapping is `sources[]` in
`data/cms-dataset-registry.json`:

```json
"sources": {
  "hospice":     { "externalIdentitySource": "cms_hospice",     "identifierType": "ccn" },
  "home-health": { "externalIdentitySource": "cms_home_health", "identifierType": "ccn" }
}
```

`scripts/cms-archive.js` contains no identity-source string at all and never
references `ProviderExternalIdentity`. A test asserts both properties.

Both use the CMS Certification Number, published in every relevant CSV under the
identical header `CMS Certification Number (CCN)`. CCNs are **strings**: they are
six characters, roughly 11 of 13 hospice CCNs we hold begin with a zero, and the
first two characters are a state code. Nothing in this pipeline coerces them to
numbers.

They are archived independently and fail independently. A home-health failure is
never reported as a hospice success.

---

## Dataset registry

`data/cms-dataset-registry.json` is tracked, and is the fail-closed schema
contract. Each entry carries:

| field | meaning |
| --- | --- |
| `source` | `hospice` or `home-health` |
| `logicalKey` | stable local name, e.g. `general`, `agencies`. Both sources define a `zip`; they are distinct because the key is scoped by source |
| `datasetId` | CMS Provider Data Catalog identifier, when stable |
| `titlePattern` | used **instead of** `datasetId` when the identifier is not proven stable |
| `expectedTitle` | human reference |
| `required` | all datasets are currently `true`. A `false` entry would still be archived-around, but an incomplete release throws and exits non-zero |
| `expectedHeaders` | the exact CSV header row we expect |

**Download URLs are deliberately not stored here.** CMS renames files every
release (`Hospice_Provider_May2026.csv` and so on), so URLs are resolved from the
metastore on every run. Storing them would guarantee staleness.

### HHCAHPS is resolved by title pattern, not by identifier

The home-health patient-survey datasets embed the reporting period in the title:
`Home Health Care - Patient Survey (HHCAHPS) 2025Q1 to 2025Q4`. At any moment
CMS publishes exactly one of each kind, so **we cannot observe from a
point-in-time catalog whether the identifier is reused across period rolls or
reminted.** Rather than guess, `hhcahps_provider` is resolved by:

```
^Home Health Care - Patient Survey \(HHCAHPS\) \d{4}Q\d to \d{4}Q\d$
```

and requires **exactly one** match. The resolved identifier is recorded in the
manifest for provenance.

`hhcahps_provider` is **`required: true`**. Resolution is deterministic, so
there is no reason to tolerate ambiguity: the failure we care about is CMS
changing, removing or duplicating the dataset and the archive continuing to look
healthy while HHCAHPS history quietly stops accumulating.

| condition | outcome |
| --- | --- |
| exactly one match | continue |
| zero matches | **home-health source fails**, exit 1 |
| more than one match | **home-health source fails**, exit 1, candidates listed, first result never chosen |
| download failure | **home-health source fails**, exit 1 |
| header drift | **home-health source fails**, exit 1 |
| checksum/write failure | **home-health source fails**, exit 1 |

A failed home-health run does not affect hospice: the two are independent matrix
jobs. Because CMS leaves a release in place until the next one, re-running after
the cause is fixed still captures it.

Separately, if a dataset were ever marked `required: false` and skipped, the
partial archive is still written **but the run throws and exits non-zero**. An
`incomplete` release can never be reported as success.

---

## Schema drift detection

Every dataset's CSV header is parsed and compared against `expectedHeaders`
**before** anything is written. Any difference aborts the archive for that
source. Detected and reported separately:

- missing expected columns
- unexpected added columns (**new columns are not silently accepted**)
- renamed columns, reported as a rename rather than as an unrelated
  missing/unexpected pair
- duplicate column names
- empty header
- malformed header (blank column names)
- same columns in a different order

The error names the source, logical key, resolved dataset id, expected columns,
actual columns, and the missing and unexpected sets, so the change can be
reviewed deliberately. **The registry is never auto-updated.** Updating
`expectedHeaders` is a human decision recorded in a commit.

---

## Releases and manifests

```
reports/cms-archive/
  2026-05-01/            legacy hospice layout, still read, never rewritten
  2026-08-19/            legacy hospice layout
  hospice/<releaseKey>/
  home-health/<releaseKey>/
```

`reports/` is gitignored: archives are data, not source. In CI they are published
as GitHub Release assets tagged `cms-<source>-<releaseKey>`.

The release key is the newest `modified` date across the datasets that actually
resolved. Each release directory holds one `<logicalKey>.csv.gz` per dataset plus
`manifest.json`:

- release level — `releaseKey`, `source`, `schemaVersion`, `capturedAt`,
  `catalog`, `datasetCount`, `expectedDatasetCount`, `status`
  (`complete` / `incomplete`), `skipped[]`, `rowCountDeltas[]`
- per dataset — `source`, `logicalKey`, `datasetId`, `title`, `modified`,
  `sourceUrl`, `rawBytes`, `gzipBytes`, `sha256Raw`, `rowCount`, `headers`,
  `archivedAt`

Historical manifests written by the previous version are read as-is and are
never rewritten.

### Row counts are reported, not enforced

Row-count movement versus the prior release of the same logical dataset is
computed and printed, absolute and percentage. It does **not** fail the archive.
We have no evidence-based anomaly threshold yet, and the hospice universe
legitimately moved by 2.7% in a single quarter. Schema drift fails closed; row
counts are currently observation.

---

## Idempotency

**Policy: archive immutability is defined by CMS metadata.** Once a release key
is captured it is never re-downloaded. This is a deliberate choice: revalidating
would mean re-fetching ~135 MB of hospice data every run to compare bytes we
already hold, for an event we have never observed.

What this **does** guarantee:

- A release key already archived is skipped, with no download.
- Legacy top-level hospice directories still count as archived, so the layout
  change cannot cause a 135 MB re-download or a duplicate capture.
- If a release key is already archived but CMS now reports a **different**
  `sourceUrl` or `modified` for it, that is treated as suspicious and **fails**.
- `sha256Raw` in each manifest fixes the bytes **we captured**, so tampering with
  or corruption of an archived file is detectable locally at any time.
- Existing archives are never overwritten, edited or deleted.

What this **does not** guarantee — stated plainly so no one relies on it:

- **If CMS serves different bytes under an identical `releaseKey`, `sourceUrl`
  and `modified` timestamp, we will not detect it.** We do not re-download known
  releases, so there is nothing to compare. `sha256Raw` protects the integrity of
  what we archived and of first capture; it says nothing about upstream drift
  after that point.

If that ever needs to change, the fix is a separate periodic revalidation job
with its own schedule and cost budget — not a change to this pipeline.

---

## Commands

```bash
node scripts/cms-archive.js --source hospice
node scripts/cms-archive.js --source home-health
node scripts/cms-archive.js --all
node scripts/cms-archive.js --source hospice --print-key
node scripts/cms-archive.js --source hospice --dry-run
node scripts/cms-archive.js --source home-health --probe   # headers only, writes nothing
node scripts/cms-archive.js --list
node scripts/test-cms-archive.js
```

`CMS_ARCHIVE_DIR` overrides the archive location. `CMS_REGISTRY_PATH` overrides
the registry, used by tests.

A monthly GitHub Action (`.github/workflows/cms-archive.yml`, 07:00 UTC on the
3rd) runs both sources as independent matrix jobs with `fail-fast: false`, and
writes a per-source summary containing release key, datasets, row counts, schema
validation status and checksum status.

---

## Relationship to ProviderExternalIdentity

CMS archive data and our Provider records stay separate.

```
CMS release archive        (this pipeline — files on disk / release assets)
        |
        |  future ingestion, not built yet
        v
CMS facility data          (NOT IMPLEMENTED — no tables exist)
        |
        |  source + CCN
        v
ProviderExternalIdentity   (deployed; 13 accepted cms_hospice identities)
        |
        v
Provider
```

`ProviderExternalIdentity` is the only bridge. CMS attributes are never written
onto `Provider`. The archive pipeline does not read or write either table.

---

## Database models (Phase A)

Three tables exist. **No CMS data has been ingested into any of them yet** — this
is the storage foundation only, and there is no ingestion code.

### Identity namespace

`CmsRelease.source` and `CmsFacility.source` use the **external identity**
namespace — `cms_hospice`, `cms_home_health` — *not* the archive-family names
(`hospice`, `home-health`). This is deliberate: it lets
`ProviderExternalIdentity (source, externalId)` line up with
`CmsFacility (source, ccn)` without translation. The archive pipeline converts
via `sources[]` in the registry, which remains the only sanctioned bridge
between the two namespaces.

### CmsRelease

One ingested CMS dataset-family release. Everything loaded from CMS points at
the release it came from, so any row is traceable to specific archived bytes.

| field | notes |
| --- | --- |
| `id` | uuid |
| `source` | `cms_hospice` \| `cms_home_health` |
| `releaseKey` | max `modified` across the family's datasets in one capture — see below |
| `capturedAt` | when the archive captured it (`manifest.capturedAt`) |
| `ingestedAt` | when it was loaded into the database, defaults to now() |
| `datasetCount` | datasets in the archived release |
| `manifestSha256` | sha256 over the **raw bytes** of the release's `manifest.json` — see below |

`@@unique([source, releaseKey])`. Scoped by source because the two families
publish on independent schedules and could coincide on a date — `releaseKey`
alone is not unique.

Per-file detail (per-dataset `sourceUrl`, `sha256Raw`, row counts, headers)
deliberately stays in the archive manifest. Only release-level facts that
database rows depend on are duplicated.

#### `releaseKey` — exact semantics

`scripts/cms-archive.js` computes it as:

```js
releaseKeyOf = (resolved) =>
  resolved.filter(r => !r.skipped).map(r => r.modified).filter(Boolean).sort().pop()
```

the **maximum `modified` date across the datasets resolved for that family in a
single archive capture** (ISO dates, so a lexicographic sort is chronological).

It is an **archive-capture identifier, not a CMS dataset release date.** The
home-health release `2026-06-10` contains four datasets modified `2026-05-27`
and one modified `2026-06-10`; the key is the max, and no single dataset is
"the" release.

Can two archive manifests for one source legitimately share a `releaseKey`? In
principle yes — if CMS republished a dataset whose `modified` is *not* the
maximum, the key would be unchanged. In practice the archiver forbids it: a
known key whose `sourceUrl` or `modified` has changed **fails** rather than
producing a second archive. So the archive guarantees at most one release per
`(source, releaseKey)`, and **`@@unique([source, releaseKey])` matches that
guarantee exactly.**

#### `manifestSha256` — exact contract for Phase B

- Hashed input is the **raw bytes of the release's `manifest.json`** as the
  archiver wrote it. **Not** canonicalised JSON, not a re-serialisation.
- The manifest contains `sha256Raw` for **every** dataset file in the release.
  So this one value transitively pins every archived byte: match the manifest
  hash, and every CSV behind it is fixed.
- It is nullable because a release could in principle be ingested from a source
  whose manifest is unavailable. Phase B should populate it in every normal path.
- It lets any database row be traced to a specific archived release, and lets an
  archive be verified as the one that produced current state.

#### Why there is no `status` column

The Phase A draft carried `status ("complete" | "incomplete")`. It was removed.
Archive V2 is fail-closed: an incomplete source archive **throws and exits
non-zero**, so no incomplete release is ever published or archived as usable.
Phase B will therefore never ingest one, and the column would be a constant
`"complete"` on every row — a workflow state we do not have. Ingestion refusing
an incomplete manifest is the honest place for that check, not a column.

### CmsFacility

One CMS-certified facility, independent of whether it is a Best Hospice
Provider. Most rows will be competitors — that is the point.

| field | required | notes |
| --- | --- | --- |
| `source`, `ccn` | yes | natural key |
| `name`, `address`, `city`, `state`, `zip` | yes | 100% populated in both families |
| `county` | no | hospice publishes `County/Parish`; the home-health file has **no county column** |
| `phone` | no | 99.1% / 96.3% populated; formats differ by family, stored verbatim |
| `ownershipType` | no | 76.6% / 82.7% populated; vocabularies differ (`For-Profit` vs `PROPRIETARY`), stored verbatim, no cross-family mapping implied |
| `certificationDate` | no | `@db.Date` |
| `firstSeenReleaseId`, `lastSeenReleaseId` | yes | relations to `CmsRelease` |

`@@unique([source, ccn])`.

### CmsFacilityServiceArea

ZIP codes CMS reports a facility as serving. `@@unique([facilityId, zip])` —
verified against the source, where `(ccn, zip)` has zero duplicates in either
family. Roughly 915k rows at national scale (hospice ~350k, home health ~566k).

It carries a denormalised `source`. That is deliberate and buys two things: it
makes the composite foreign keys below possible, and it lets the hot
competitor-overlap query use `(source, zip)` directly instead of joining
`CmsFacility` to filter by family.

### Data types — validated against the real CSVs

- **CCN is `String`, never numeric.** 1,575 of 6,669 hospice CCNs (24%) are
  alphanumeric in the form `A01500`, and 633 hospice plus 1,762 home-health CCNs
  carry leading zeros. A numeric column would corrupt a quarter of the hospice
  universe outright.
- **ZIP is `String`.** Always 5 characters; 271 hospice and 516 home-health
  facility ZIPs begin with zero, and ~45k service-area ZIPs do.
- **`phone` is `String`.** Hospice publishes `(602) 855-3500`, home health
  publishes `6028553500`. Normalising is an ingestion concern.
- **`certificationDate` is `DateTime? @db.Date`.** CMS publishes `MM/DD/YYYY`
  uniformly in both families — 100% of hospice rows and all but one home-health
  row parse. It is a **date**, so it maps to Postgres `DATE`, not `timestamp`:
  there is no time component to invent and no timezone to get wrong. Blank and
  `-` sentinels normalise to null.

### Relations and delete behaviour

All five foreign keys are `ON DELETE RESTRICT`, by omission, matching every
other relation in this schema. Deleting a release must never erase the
facilities observed in it, and deleting a facility must never erase its
service-area history. An *unreferenced* release can still be deleted.

**All five are composite on `source`**, which is what makes source consistency a
database guarantee rather than an ingestion convention:

| foreign key | columns | references |
| --- | --- | --- |
| `CmsFacility_firstSeenReleaseId_source_fkey` | `(firstSeenReleaseId, source)` | `CmsRelease(id, source)` |
| `CmsFacility_lastSeenReleaseId_source_fkey` | `(lastSeenReleaseId, source)` | `CmsRelease(id, source)` |
| `CmsFacilityServiceArea_facilityId_source_fkey` | `(facilityId, source)` | `CmsFacility(id, source)` |
| `CmsFacilityServiceArea_firstSeenReleaseId_source_fkey` | `(firstSeenReleaseId, source)` | `CmsRelease(id, source)` |
| `CmsFacilityServiceArea_lastSeenReleaseId_source_fkey` | `(lastSeenReleaseId, source)` | `CmsRelease(id, source)` |

Supporting `@@unique([id, source])` exists on both `CmsRelease` and
`CmsFacility` purely as the target for these.

Before this, the database happily accepted a `cms_hospice` facility whose
`firstSeenRelease` was a `cms_home_health` release, a facility whose first- and
last-seen releases straddled two sources, and a hospice service area pointing at
a home-health release. All three are now rejected, and all three have tests.

`CmsFacility` and `CmsFacilityServiceArea` each carry two relations to
`CmsRelease`, so Prisma requires explicit relation names
(`CmsFacilityFirstSeen`, `CmsFacilityLastSeen`, `CmsServiceAreaFirstSeen`,
`CmsServiceAreaLastSeen`).

### The ProviderExternalIdentity join is LOGICAL, not a foreign key

```sql
ProviderExternalIdentity (source, externalId)  =  CmsFacility (source, ccn)
```

Prisma could express this as a composite relation, and it was considered.
It is deliberately **not** implemented, for two reasons:

1. It would make every identity row require a matching `CmsFacility`. Production
   holds 13 accepted identities today and `CmsFacility` is empty, so the
   constraint could not be satisfied.
2. It would change what an identity *means*. An accepted identity is a recorded
   human decision; it must not become invalid because ingestion has not run, or
   because CMS dropped a facility from a later release.

A test asserts `ProviderExternalIdentity` still has exactly one foreign key (to
`Provider`), that the logical join resolves, and that an identity can exist with
no ingested facility.

### History boundary

`CmsFacility` and `CmsFacilityServiceArea` hold **current state**, updated in
place, with `firstSeenRelease` / `lastSeenRelease` bracketing observation. That
is enough to answer "when did this first appear", "is this still present", "who
entered the market", "who disappeared".

Rows are never deleted when they stop appearing in CMS, so "current" is a
*query*, not a stored flag. A row is CURRENT when its `lastSeenReleaseId` is the
latest release for its source; otherwise it is HISTORICAL:

```sql
-- Which facilities CURRENTLY serve ZIP 85016?
SELECT f.*
FROM "CmsFacilityServiceArea" sa
JOIN "CmsFacility" f ON f.id = sa."facilityId"
WHERE sa.source = 'cms_hospice'
  AND sa.zip    = '85016'
  AND sa."lastSeenReleaseId" = (
        SELECT id FROM "CmsRelease"
        WHERE source = 'cms_hospice'
        ORDER BY "releaseKey" DESC
        LIMIT 1);
```

Drop the `lastSeenReleaseId` predicate and the same query returns the full
history, including relationships CMS has since dropped. **No `active` boolean is
needed** — it would duplicate state already implied by `lastSeenReleaseId` and
would have to be rewritten across ~915k rows on every refresh. Tested both ways.

Explicitly **deferred, and not built**:

- **`CmsMeasure`** — append-only, release-stamped quality and CAHPS history.
- **`CmsFacilityHistory`** — per-release snapshots of slow-changing attributes
  such as ownership or address.

### Indexes and scale

Sized for ~6,669 hospice and ~12,460 home-health facilities, and ~915k
service-area rows.

| index | serves |
| --- | --- |
| `CmsFacility @@unique([source, ccn])` | `WHERE source=? AND ccn=?`, and `WHERE source=?` via the leftmost prefix |
| `CmsFacility @@index([source, state])` | `WHERE source=? AND state=?` |
| `CmsFacility @@index([source, zip])` | `WHERE source=? AND zip=?` |
| `CmsFacility @@index([firstSeenReleaseId])` `@@index([lastSeenReleaseId])` | market entry / exit diffing; also keeps `RESTRICT` checks cheap |
| `CmsFacilityServiceArea @@unique([facilityId, zip])` | `WHERE facilityId=?` via the leftmost prefix |
| `CmsFacilityServiceArea @@index([source, zip])` | `WHERE source=? AND zip=?` — the competitor-overlap query, and the one that matters most at 915k rows. Overlap is always compared within a service line, so it is source-scoped in practice |
| `CmsFacilityServiceArea @@index([lastSeenReleaseId])` | staleness and pruning |

No standalone `source` index: the unique constraint's leftmost prefix already
covers it. No `firstSeenReleaseId` index on the 915k service-area table — that
column is only read during whole-release diffing, and the second index is not
worth the write cost until there is evidence it is needed.

### Known ingestion caveat, recorded now

The hospice `zip` and `general` datasets are published with different `modified`
dates and are not atomic. In the 2026-08-19 release, `zip.csv` references
**242 CCNs that do not appear in `general.csv`**. Because
`CmsFacilityServiceArea.facilityId` is a real foreign key, ingestion will have to
skip and report those orphans rather than fail. Home health showed zero orphans.

Also note the existing `NA` sentinel set in `scripts/cms-ingest.js` does not
include `-`, which home health uses widely. Ingestion will need it.

---

## Not implemented

Named explicitly so this document is not mistaken for a description of a larger
system than exists:

- **No database ingestion.** `CmsRelease`, `CmsFacility` and
  `CmsFacilityServiceArea` exist as tables, but nothing writes to them. There is
  no ingestion code and no CMS data in any database.
- **No `CmsMeasure`** and **no `CmsFacilityHistory`.** Both are deferred.
- No home-health identity matching. No Provider currently holds a
  `cms_home_health` identity.
- No Market Intelligence surface is provider-visible.
- No `careType` change. Whether a given `home` Provider is a Medicare-certified
  home health agency or a non-medical personal-care agency is **not** encoded
  anywhere, and the archive pipeline makes no such claim.
