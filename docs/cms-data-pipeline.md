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

## Phase B — hospice ingestion

`scripts/import-cms-hospice-data.js` loads one **archived** hospice release into
`CmsRelease`, `CmsFacility` and `CmsFacilityServiceArea`. Quality, CAHPS and
benchmark datasets are **not** ingested; `CmsMeasure` remains deferred.

### Archived data only, and Archive V2 only

The input is always an archive on disk under `reports/cms-archive/`. A live CMS
endpoint is never an ingestion source — that is the archiver's job, and keeping
the two separate is what makes ingestion reproducible.

**Database ingestion requires an Archive V2 manifest.** `source`, `status`,
`datasetCount` and per-file `headers` must be **recorded facts**. A legacy
pre-V2 manifest is **refused**:

```
Archive V2 manifest required for CMS ingestion. This archive is missing recorded
manifest fact(s): schemaVersion >= 2, source, status, datasetCount, ...
  Re-archive this release with the current archiver:
    node scripts/cms-archive.js --source hospice
  The importer will not infer archive metadata.
```

Phase B has exactly one archive contract. The importer never reconstructs,
infers or repairs archive metadata — that is precisely what Archive V2 exists to
guarantee, and having two contracts would undermine it.

**Legacy V1 archives are preserved on disk as historical evidence** and remain
readable by the archiver for history purposes. They are simply not valid
ingestion input. `reports/cms-archive/2026-05-01` is such an archive.

When both layouts hold the same release key, the V2 archive under
`reports/cms-archive/hospice/<key>/` is the one selected.

#### Re-archiving an existing release

`2026-08-19` originally existed only as a V1 archive. It was re-captured with
the current archiver into a temporary directory and **all six raw dataset
sha256 values matched the preserved V1 archive byte-for-byte**, proving CMS
still serves identical bytes. The archiver-produced V2 manifest was then
installed at `reports/cms-archive/hospice/2026-08-19/`; the V1 archive at
`reports/cms-archive/2026-08-19/` was left byte-untouched. No manifest was
hand-authored.

### Namespace mapping

Archive family **`hospice`** maps to database source **`cms_hospice`** via
`sources[]` in the registry. The two strings are never compared directly.

### Archive validation — fail closed

Before anything is read into memory: manifest exists and parses · `releaseKey`
matches the archive directory and is `YYYY-MM-DD` · source is hospice · the
release is complete · `general` and `zip` are present with their `.csv.gz` on
disk · every used file decompresses · **every used file's sha256 matches
`sha256Raw`** · every header matches the registry contract exactly.

**Legacy (pre-V2) manifests** are accepted only when the facts V2 records can be
independently *derived and verified* from content: `source` from every
`datasetId` matching the hospice registry, completeness from every required
dataset being present with a verified checksum, `datasetCount` from the manifest
file list. Each derivation is printed as a `NOTE`. Nothing is repaired or
written back. The `2026-05-01` archive predates `datasetId` recording entirely,
so its source cannot be verified and it is **refused** — which is correct.

### releaseKey and manifestSha256

`releaseKey` keeps Archive V2 semantics exactly: the max `modified` across the
datasets in one capture, not a single dataset's publication date.
`manifestSha256` is sha256 over the **raw bytes** of `manifest.json`, hashed
before any parse or re-serialisation — a 64-character lowercase hex digest.
Hashing a re-serialised parse gives a different value, and a test asserts both
that the digest matches `^[a-f0-9]{64}$` and that it equals `shasum -a 256` of
the file.

### Chronological ingestion

Current-state semantics depend on `lastSeenReleaseId` being the newest release,
so ingestion is ordered. Chronology is decided by comparing the requested
release **R** against the **latest already-ingested release L for that source** —
never by whether a `CmsRelease` row for R happens to exist:

| situation | behaviour |
| --- | --- |
| no existing release for the source | allowed |
| `R > L` | allowed — normal later-release ingestion |
| `R == L` | idempotent re-run, subject to the conflict rules |
| `R < L` | **refused** — no backfill, no override |

**An already-ingested historical release that has since been superseded is still
`R < L`, and is refused.** It is an out-of-order ingestion attempt, not an
idempotent re-run: replaying it would move `lastSeenReleaseId` backwards and
restore stale descriptive values, silently breaking the current-state invariant.
"Same release" therefore means *R equals the latest ingested release*, not merely
*a row for R exists somewhere*.

The rule is enforced at two checkpoints, neither conditioned on R already
existing: once during planning — so a DB-backed **dry run refuses it too** and
never labels it an idempotent re-run — and once inside the mutation transaction
immediately after the advisory lock, which is authoritative for writes. A refusal
is a non-zero exit with zero writes: no facility changes, no service-area
changes, no `lastSeen` changes, no descriptive-field changes.

`--no-db` cannot know database chronology and remains archive-validation-only.

Keys are `YYYY-MM-DD`, so lexical ordering is chronological; the format is
validated rather than assumed.

### Idempotency and conflict

A re-run of the same release must present the same archive. If the stored
`manifestSha256`, `capturedAt` or `datasetCount` disagree, it is a **CONFLICT**
and zero rows are written. If the stored `manifestSha256` is **NULL** the re-run
also fails: a null hash cannot prove the archive is the one already ingested,
and blessing different bytes silently is worse than an explicit failure. A true
no-op re-run reports `UNCHANGED` and **opens no transaction at all**.

### First/last seen

New rows get `firstSeen = lastSeen = this release`. Rows seen again keep
`firstSeenReleaseId`, move `lastSeenReleaseId` forward, and take the new
release's descriptive values. `lastSeenReleaseId` **only ever moves forward** —
the chronology rule above is what guarantees it, by refusing any release older
than the latest ingested one, including one that was ingested previously. **Nothing is ever deleted**: a facility or service
area absent from a newer release keeps its old `lastSeenReleaseId`, which is
precisely how disappearance is recorded. A changed name or address never creates
a second row — `(source, ccn)` is the identity.

### Orphan hospice ZIP rows

CMS publishes `general` and `zip` with different `modified` dates, so the ZIP
file references certifications the facility file does not contain. In the
`2026-08-19` release that is **242 distinct CCNs across 7,329 rows, 2.10% of the
ZIP dataset**. Those rows are skipped, and the orphan row count and distinct
orphan CCN count are always printed to the console. The **full list of distinct
orphan CCNs is written only to the JSON report**, and only when `--json <path>`
is supplied — it is never printed to the console. No placeholder facility is created, nothing is
attached to another facility, and no fuzzy matching happens. This does **not**
fail the release. No percentage threshold is enforced — the structural checks
(header contract, checksums, CCN format) are the real guard, and an arbitrary
band would fail legitimately volatile releases.

### Missing-value normalisation

`-` is a CMS sentinel and is normalised to null, alongside blank,
`Not Available`, `Not Applicable` and `N/A`. In the real `2026-08-19` hospice
file it appears in 6,057 `Address Line 2`, 61 `County/Parish` and 60
`Telephone Number` values. It is applied **only to nullable descriptive
fields** — never to an identifier — and no identity column in the observed data
ever holds a sentinel-looking value. Rows missing a required identity or
location field are skipped and reported, never fabricated.

`certificationDate` is passed to Postgres as a `YYYY-MM-DD` **string**. Passing a
JS `Date` makes the driver serialise in local time, and `::date` then truncates
to the previous day in any negative UTC offset — a silent off-by-one that was
caught in rehearsal against real data.

```bash
node scripts/import-cms-hospice-data.js --list
node scripts/import-cms-hospice-data.js --release 2026-08-19 --no-db   # archive only
node scripts/import-cms-hospice-data.js --release 2026-08-19           # dry run, zero writes
node scripts/import-cms-hospice-data.js --release 2026-08-19 --write

# derive the release-scoped production authorization (never touches a database)
node scripts/import-cms-hospice-data.js --release 2026-08-19 --print-production-authorization

# a production-classified target additionally requires that exact token;
# --write is still required separately for any write to happen
node scripts/import-cms-hospice-data.js --release 2026-08-19 \
  --production-authorization <64-hex> --write
```

### Production authorization

Production is **refused by default and stays refused by default**. There is no
`--force-prod`, `--allow-prod`, `--skip-prod-guard`, `--unsafe` or `--override`,
and none may ever be added.

Database targets are classified into three kinds from the connection string
alone — raw, percent-decoded, and parsed hostname/path/query:

| kind | matched by | behaviour |
| --- | --- | --- |
| `SHADOW` | `besthospice_shadow_2`, `besthospice_shadow_2_user`, `dpg-d60g7h0gjchc73f306j0-a`, plus the display name `besthospice-shadow-2` | **always refused. There is no authorization path, ever.** |
| `PRODUCTION` | `besthospice_db`, `besthospice_db_user`, `dpg-d5hhmb4hg0os7380cecg-a` | refused unless a release-scoped authorization is supplied |
| `HOSTED_UNKNOWN` | any `render.com`, RDS, Supabase or Neon host, **or any Render internal host id** (`^dpg-[a-z0-9]{6,}(-[a-z])?$` on the parsed hostname) | **always refused. No authorization path** — an unidentified managed database cannot be proven safe |
| `NON_PRODUCTION` | a disposable local database | unchanged; no authorization required or accepted |

Order is `SHADOW` → `PRODUCTION` → `HOSTED_UNKNOWN` → `NON_PRODUCTION`. Shadow is
matched first because it lives on the same provider as production and must never
fall through into an authorizable class. Keeping `HOSTED_UNKNOWN` separate is what
stops the authorization from becoming a general-purpose key to any remote
database.

Two properties make this reliable:

- **Identifiers are the strings that actually appear in a connection URL** —
  database name, role name and Render host id — not the Render dashboard display
  name, which never appears in one.
- **Identifiers match on boundaries, not as bare substrings.** `besthospice_db1`
  is *not* the production database `besthospice_db`, so a production
  authorization can never reach it; a Render database that is not positively
  recognised classifies as `HOSTED_UNKNOWN` and has no authorization path. The
  host-id rule is applied only to the parsed hostname, so a local database merely
  *named* something like `dpg-scratch-a` stays `NON_PRODUCTION`.

#### The authorization is a one-time, release-scoped token

    --production-authorization <64 lowercase hex characters>

The expected value is `sha256` of exactly these bytes, newline-terminated:

```
cms-hospice-production-ingest
source=cms_hospice
releaseKey=<exact releaseKey>
manifestSha256=<exact manifestSha256 of that archive's manifest.json>
```

It is **not a secret and not authentication.** Anyone holding the archive can
recompute it, and it is useless against an operator who already has production
credentials. **Possession of the production database credential remains the
privileged thing, and it sits outside this threat model entirely** — anyone
holding it can bypass this script altogether with `psql`. Treat the credential
accordingly; the token protects nothing about it. That is not the threat this
addresses. What it prevents is an
accidental production run, a stale command re-executed later, a line copy-pasted
from a different release, and — most importantly — the existence of any reusable
bypass at all: a token is worthless for any other release, manifest or source, so
no single flag can ever authorize "production" in general.

Reproduce it independently at any time:

```bash
printf 'cms-hospice-production-ingest\nsource=cms_hospice\nreleaseKey=%s\nmanifestSha256=%s\n' \
  "$RELEASE" "$MANIFEST_SHA" | shasum -a 256
```

**Derive the token freshly from the validated archive at the moment of
execution.** Do not copy one out of a runbook, a ticket, a chat message or an old
terminal transcript — a stale token is exactly the failure this interlock exists
to catch, and re-deriving it costs one command. Derive it from a validated
archive:

```bash
node scripts/import-cms-hospice-data.js --release 2026-08-19 --print-production-authorization
```

`--print-production-authorization` validates the Archive V2 contract first, never
contacts a database, never constructs a Prisma client, never mutates anything, and
refuses to emit a token for an archive that would not pass ingestion validation.
It cannot be combined with `--write` or with `--production-authorization`.

#### What authorization does and does not do

Authorization permits the **connection** to a production-classified target. It is
not a write switch:

- **Authorization does not imply `--write`.** The default is still a dry run; a
  write still requires an explicit `--write` in addition to the token.
- Every other check still runs unchanged behind it: Archive V2 validation, the
  manifest conflict rules, chronology (`R < L` refused, including a superseded
  release), the advisory lock, the transaction, and the postconditions.
- A token valid for an older release does **not** relax chronology. A token valid
  for a tampered archive does **not** relax the manifest conflict check.
- A failed production attempt never prints the expected token, the URL, or any
  credential.

The token is checked only after the archive is fully validated, so the release
facts it is scoped to are already immutable at that point. Order is: CLI shape →
archive selection and V2 validation → release facts known → target classified →
shadow/unknown refused unconditionally → production requires the exact token →
Prisma client constructed → normal planning, chronology and write logic.

The first production ingestion is a separate, explicitly authorized checkpoint
and is not performed by any automated path.

### Commands and safety

Dry run is the default. `--no-db` never constructs a Prisma client, and
`--no-db` and `--write` are **mutually exclusive** — supplying both is a usage
error (exit 2), not a silently resolved contradiction. `--release` and `--json`
each require a value; a missing value, or a value that looks like another flag,
is a usage error (exit 2) rather than a silent fallback. Omitting `--release`
selects the latest local archive deterministically and prints it prominently,
but `--release` is preferred for any real execution.

Planning never loads the existing `CmsFacilityServiceArea` table into memory.
Intended `(ccn, zip)` pairs are streamed to Postgres in chunks and classified by
a join against `unnest()`, so peak memory is one chunk regardless of how large
the table grows. A dry run still opens no transaction and creates no temporary
objects.

Ingestion is serialised per source by `pg_advisory_xact_lock`, taken as the very
first statement of the mutation transaction — before the chronology re-check.
Two concurrent later releases would otherwise both pass chronology under READ
COMMITTED and let commit order, rather than `releaseKey`, decide the surviving
`lastSeenReleaseId`. The lock is transaction-scoped, so it is released on commit
or rollback with no cleanup and no lock table.

The guard applies to **every mode that opens a connection**, not just `--write`.
There is no production override and no bypass flag; the only path to a
production-classified target is the release-scoped authorization described in
[Production authorization](#production-authorization), which permits a
connection and nothing more.

### Transaction

Parse and validate happen entirely outside the transaction. Inside one Prisma
transaction: preconditions are re-checked, the release is created or reused,
facilities and service areas are upserted in batches, and postconditions are
asserted before commit. Any failure rolls back the release together with all
facility and service-area changes — no `CmsRelease` row is left behind.

Bulk upserts use parameterised `INSERT … ON CONFLICT` inside the Prisma
transaction. At ~342k service-area rows per release, per-row client calls would
be untenable; `firstSeenReleaseId` is deliberately absent from every `DO UPDATE
SET` list so it can never be overwritten.

---

## Internal reference accounts (`Provider.internalRole`)

`Provider.internalRole` is a nullable string marking a provider record kept for
internal operational or reference purposes rather than as a real participating
provider. It is `NULL` for every real provider, which is why the column needed no
backfill. A string rather than a boolean, so future internal account types need
no new column. First and currently only value: **`cms_reference`** — the account
used to exercise the CMS provider-facing pipeline end to end.

**Invariant.** Any provider with a non-null `internalRole` is excluded from every
public and business behaviour, while **keeping authenticated dashboard access**.
Exercising the real provider experience is the entire point of such an account, so
locking it out of the dashboard would defeat it.

Three forms express the rule and must agree exactly. All three key off `NULL` and
nothing else, so an empty string is treated as *internal* — the fail-safe
direction, where a stray value excludes rather than exposes.

| form | definition | used by |
| --- | --- | --- |
| `isInternalProvider(provider)` | `provider.internalRole != null` | JS filters |
| `PUBLIC_PROVIDER_WHERE` | `{ internalRole: null }` | Prisma reads |
| `INTERNAL_PROVIDER_SQL` | `"internalRole" IS NOT NULL` | hand-written SQL |

`PUBLIC_PROVIDER_WHERE` is deliberately a single key rather than an `OR`, so it
composes into an existing `where` without colliding with one.

### Excluded

Client lead routing · job lead fan-out · discharge-referral fan-out · the public
directory and search APIs · city/state and `/:service/...` location pages ·
location-page existence and counts · `sitemap.xml` and provider URLs · the public
`/provider/:slug` detail page (404, never a redirect) · schema.org JSON-LD ·
Stripe checkout initiation.

### Retained

Authenticated dashboard access · the provider–user relationship · the Market
Intelligence page · admin and unfiltered reads · Stripe **webhook** resolution,
which is untouched so events for real providers keep resolving normally.

### Public list vs dashboard account selection

`Provider.internalRole` is **Provider-level**, and the one place it must *not*
hide an account is the flow that lets its own operator log in. Two endpoints keep
those concerns apart:

| endpoint | filtered? | returns | used by |
| --- | --- | --- | --- |
| `/api/public/providers` | **yes** — `PUBLIC_PROVIDER_WHERE` | `id, name, email` | `index.html`, `hospice-az.html`, `home-care-az.html`, `home-care-landing.html`, `home-care-search.html` — all for the "N providers" count badge only |
| `/api/provider-auth/providers` | **no** — internal accounts included | `id, name` only | `provider-dashboard.html` signup/login selector |

The second is an **account-selection bootstrap, not a public directory.** It is
necessarily unauthenticated: the dashboard needs a `providerId` to send to
`/api/provider-auth/signup-start` and `/api/provider-auth/login`, so the list must
be fetchable before any credential exists. Authenticating it would make
first-time signup impossible.

Its response is therefore the strict minimum the `<select>` renders — `id` and
`name`, which is **less** than the public endpoint exposes. No contact details,
no billing or subscription data, no CMS data, no `internalRole`, no tokens.

**Known tradeoff:** because the login UX selects a provider before authenticating,
an internal account's `id` and `name` are visible to an unauthenticated caller of
this endpoint. That is inherent to the current selector-based login design, not
something the split introduced. It is accepted deliberately: the alternative —
looking the provider up only after an email is entered — is a login redesign, and
the exposure is limited to a name and an opaque UUID that grant no access on their
own. Revisit it if provider login is ever reworked.

### Not the same thing as an identity

`ProviderExternalIdentity` remains **authoritative identity data**. It means
*"this Best Hospice provider IS that external provider"* — enforced by
`@@unique([source, externalId])`, and recorded with `confidence`, `verifiedAt` and
`verifiedBy`. It must **never** be used simply to borrow another organisation's
CMS data for testing. That is precisely what `internalRole` exists for. An
internal account may later hold a genuine identity row, but the row still asserts
real identity; the *account*, not the identity, is what is marked
non-authoritative.

## Provider CMS resolution

The authoritative chain, implemented in `cms-provider-resolver.js`:

```
Provider -> ProviderExternalIdentity -> CmsFacility -> CmsFacilityServiceArea
```

`resolveProviderCmsContext(prisma, providerId)` takes **only** a provider id.
Care type, CMS source, CCN and facility are all derived from the database; none
is ever accepted from a caller.

### Rules

- **`ProviderExternalIdentity` is authoritative.** It means *"this provider IS
  that external provider."* Resolution happens only through a real identity row.
- **The identity must be verified.** `verifiedAt` is the repo's acceptance
  marker — the identity importer writes it from the human reviewer's
  `reviewedAt`. A null `verifiedAt` is treated as not accepted.
- **Both `source` and `externalId` are required.** The facility join uses the
  composite `(source, ccn)` natural key. A CCN alone is not unique across
  sources, and joining on it would let a `cms_home_health` record answer for a
  hospice provider.
- **Ambiguous identities fail closed.** `@@unique([source, externalId])` makes a
  CCN globally exclusive, but nothing stops one provider holding several
  identities in the same source. Two verified identities returns
  `multiple_verified_identities` rather than picking one.
- **A missing facility fails closed.** A verified identity may outlive the
  ingested data — there is deliberately no foreign key between them — so this
  returns `facility_not_found`. It is a staleness signal, not licence to guess.
- **No fallback of any kind.** No provider-name match, no city/state match, no
  ZIP or service-area inference, no nearest-facility guess, no auto-created
  identity rows.
- **`internalRole` has no effect on identity resolution.** It governs public and
  business isolation only. A `cms_reference` account and a real customer use the
  identical resolver, and neither resolves without a verified identity.

### Care type to CMS source

| careType | CMS source | status |
| --- | --- | --- |
| `hospice`, `hospice-care` | `cms_hospice` | supported |
| everything else | — | `unsupported_care_type` |

The mapping is explicit and closed. It deliberately does **not** use
`normalizeCareType()`, which falls back to `hospice` for anything unrecognised —
correct for service-page routing, wrong here, because it would claim Medicare
publishes hospice data about a palliative or assisted-living provider.

`home-health` is intentionally absent. The registry maps that family to
`cms_home_health` and the archiver captures it, but no ingester writes
`CmsFacility` rows for it yet, so there is nothing to resolve to. Adding it later
is one line in `CMS_SOURCE_BY_CARE_TYPE` plus one in `IDENTIFIER_TYPE_BY_SOURCE`;
the resolver needs no redesign.

### Result states

| status | meaning |
| --- | --- |
| `resolved` | full CMS context returned |
| `provider_not_found` | no such provider |
| `unsupported_care_type` | no CMS dataset is resolved for this care type |
| `no_verified_identity` | no accepted identity for the applicable source |
| `multiple_verified_identities` | ambiguous — refusing to choose |
| `facility_not_found` | verified identity, but that facility is not ingested |

Unresolved states are ordinary, not errors: the resolver returns a structured
status rather than throwing.

### Service areas and freshness

Service areas are fetched through the relational key `(facilityId, source)`,
never independently by CCN, and ordered by ZIP so output is deterministic.
`@@unique([facilityId, zip])` already guarantees one row per ZIP, so there is no
application-level dedupe.

`CmsFacility` is **current state**, updated in place as CMS republishes, with
`firstSeenRelease` / `lastSeenRelease` bracketing observation. "Still current" is
therefore computed by comparing `lastSeenReleaseId` against the newest ingested
release for the source — it is not a stored flag.

### Runtime consumer

`GET /api/provider-intelligence/cms-context` — requires provider authentication,
resolves the authenticated provider only. There is no `providerId` parameter in
the path, query or body, so one provider cannot inspect another's CMS context.
Read-only: it creates no identity and writes nothing.

The response is an explicit projection, never raw Prisma rows. Provider email,
Stripe ids, billing mode, subscription state, `planTier` and `internalRole` are
all excluded.

**UI capability is unchanged.** `cmsQuality`, `cmsRatings`, `cahps`, competitor,
market-opportunity and reports modules all remain `coming_soon`, and
`provider-intelligence.html` does not consume this endpoint. Flipping any
capability to `available` is a separate, separately authorized step.

## Not implemented

Named explicitly so this document is not mistaken for a description of a larger
system than exists:

- **No home-health ingestion.** Only hospice is ingested. `CmsFacility` and
  `CmsFacilityServiceArea` hold `cms_hospice` rows only.
- **No CMS data in production.** Ingestion has run against disposable local
  databases only.
- **No `CmsMeasure`** and **no `CmsFacilityHistory`.** Both are deferred.
- No home-health identity matching. No Provider currently holds a
  `cms_home_health` identity.
- No Market Intelligence surface is provider-visible.
- No `careType` change. Whether a given `home` Provider is a Medicare-certified
  home health agency or a non-medical personal-care agency is **not** encoded
  anywhere, and the archive pipeline makes no such claim.
