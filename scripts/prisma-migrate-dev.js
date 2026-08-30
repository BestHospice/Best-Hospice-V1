#!/usr/bin/env node
/**
 * Guarded wrapper for `prisma migrate dev`.
 *
 * `migrate dev` is destructive against a drifted database: it detects drift and
 * offers to reset, which on this project's production database would drop 34
 * columns and 5 tables that only ever existed as raw SQL. The old
 * `npm run prisma:migrate` script pointed straight at whatever DATABASE_URL
 * happened to be loaded, which for anyone with production credentials in .env
 * meant production.
 *
 * This refuses to run unless DEV_DATABASE_URL is set explicitly, and refuses
 * outright if that URL looks like the production host.
 */
const { spawnSync } = require('child_process');

const dev = process.env.DEV_DATABASE_URL;
if (!dev) {
  console.error('Refusing to run: DEV_DATABASE_URL is not set.');
  console.error('');
  console.error('  prisma migrate dev can reset a drifted database. Point it at a');
  console.error('  scratch database explicitly:');
  console.error('');
  console.error('    DEV_DATABASE_URL=postgresql://localhost:5432/bh_dev npm run prisma:migrate:dev');
  console.error('');
  console.error('  Never a production URL. To change production, review a migration');
  console.error('  and apply it with `prisma migrate deploy`.');
  process.exit(1);
}

// Cheap belt-and-braces: refuse anything that looks like managed production.
if (/render\.com|\.rds\.amazonaws\.com|supabase\.co|neon\.tech/i.test(dev)) {
  console.error('Refusing to run: DEV_DATABASE_URL points at what looks like a hosted production database.');
  console.error('Use a local or scratch database, or apply reviewed migrations with `prisma migrate deploy`.');
  process.exit(1);
}

const r = spawnSync('npx', ['prisma', 'migrate', 'dev', ...process.argv.slice(2)], {
  stdio: 'inherit',
  env: { ...process.env, DATABASE_URL: dev }
});
process.exit(r.status == null ? 1 : r.status);
