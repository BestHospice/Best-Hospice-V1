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

## Not implemented

Named explicitly so this document is not mistaken for a description of a larger
system than exists:

- **No database ingestion.** There are no `CmsFacility`, `CmsMeasure`,
  `CmsRelease` or similar tables. None have been designed into Prisma.
- No home-health identity matching. No Provider currently holds a
  `cms_home_health` identity.
- No Market Intelligence surface is provider-visible.
- No `careType` change. Whether a given `home` Provider is a Medicare-certified
  home health agency or a non-medical personal-care agency is **not** encoded
  anywhere, and the archive pipeline makes no such claim.
