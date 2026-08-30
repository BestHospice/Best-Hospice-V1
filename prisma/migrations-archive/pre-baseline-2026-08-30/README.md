# Pre-baseline migration archive (2026-08-30)

These 16 directories are the project's original Prisma migration chain: the 15
historical migrations (2026-01-11 through 2026-03-23) plus
`20260829000000_reconcile_production_schema`.

**They are historical/audit artifacts only. They are not active migrations.**

## Why they were retired

The chain was not reproducible from an empty database. `prisma migrate deploy`
against a fresh PostgreSQL 18 database failed at migration 6 with:

```
Error: P3018   Database error code: 42P01
ERROR: relation "ProviderUserProvider" does not exist
Migration name: 20260202143853_add_plan_tier
```

`20260202143853_add_plan_tier` drops and re-adds foreign keys on
`ProviderUserProvider`, but that table is created by
`20260205_multi_provider_links`, which Prisma orders *after* it (migrations sort
lexicographically by directory name, and `20260202143853` < `20260205`).
Production was built incrementally in a different real-world order, so it never
hit the failure; a fresh database always did.

The two migrations also disagree on delete semantics: migration 7 creates the
foreign keys `ON DELETE CASCADE` and migration 6 rewrites them to `RESTRICT`.
Production has `RESTRICT`. Any repair that dropped migration 6's rewrite would
have silently given new environments cascading deletes.

`20260829000000_reconcile_production_schema` is archived too: its contents are
fully subsumed by `0_init`.

## What replaced them

`prisma/migrations/0_init/migration.sql`, generated on **2026-08-30** from the
reviewed, production-equivalent `prisma/schema.prisma` via:

```
prisma migrate diff --from-empty --to-schema-datamodel prisma/schema.prisma --script
```

It was validated on an empty PostgreSQL 18 database: it applies cleanly, both
`prisma migrate diff` directions come back empty, and introspecting the result
reproduces `prisma/schema.prisma` byte-for-byte.

## Rules

- **Do not replay these migrations.** They are outside `prisma/migrations/` on
  purpose. Prisma does not see them, and running them against anything is
  unsupported.
- **Do not move them back into the active migrations directory.**
- **Do not edit the archived SQL.** It is kept byte-identical to what was
  actually applied.
- **All future migrations are created after `0_init`.** Active migration history
  begins there.
- **Production keeps its original `_prisma_migrations` rows.** The 15 historical
  rows were deliberately left in place as an audit record. Prisma 5.22.0
  tolerates rows whose directories are absent locally: `migrate status` and
  `migrate deploy` both ignore them once a common migration exists.
