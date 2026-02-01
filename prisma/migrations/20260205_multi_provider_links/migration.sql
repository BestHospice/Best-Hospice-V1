-- Create join table for multi-location support
CREATE TABLE "ProviderUserProvider" (
  "id" TEXT NOT NULL,
  "providerUserId" TEXT NOT NULL,
  "providerId" TEXT NOT NULL,
  "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
  CONSTRAINT "ProviderUserProvider_pkey" PRIMARY KEY ("id")
);

-- Unique constraint
CREATE UNIQUE INDEX "ProviderUserProvider_providerUserId_providerId_key"
  ON "ProviderUserProvider"("providerUserId", "providerId");

-- Backfill links from legacy ProviderUser.providerId
INSERT INTO "ProviderUserProvider" ("id", "providerUserId", "providerId", "createdAt")
SELECT concat("id", '_', "providerId"), "id", "providerId", CURRENT_TIMESTAMP
FROM "ProviderUser"
WHERE "providerId" IS NOT NULL
ON CONFLICT DO NOTHING;

-- Add activeProviderId column to ProviderUser
ALTER TABLE "ProviderUser" ADD COLUMN "activeProviderId" TEXT;

-- Backfill activeProviderId from legacy providerId
UPDATE "ProviderUser"
SET "activeProviderId" = COALESCE("activeProviderId", "providerId")
WHERE "providerId" IS NOT NULL;

-- Drop old foreign key and column providerId
ALTER TABLE "ProviderUser" DROP CONSTRAINT IF EXISTS "ProviderUser_providerId_fkey";
ALTER TABLE "ProviderUser" DROP COLUMN IF EXISTS "providerId";

-- Add foreign keys
ALTER TABLE "ProviderUserProvider"
  ADD CONSTRAINT "ProviderUserProvider_providerUserId_fkey"
  FOREIGN KEY ("providerUserId") REFERENCES "ProviderUser"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ProviderUserProvider"
  ADD CONSTRAINT "ProviderUserProvider_providerId_fkey"
  FOREIGN KEY ("providerId") REFERENCES "Provider"("id") ON DELETE CASCADE ON UPDATE CASCADE;

ALTER TABLE "ProviderUser"
  ADD CONSTRAINT "ProviderUser_activeProviderId_fkey"
  FOREIGN KEY ("activeProviderId") REFERENCES "Provider"("id") ON DELETE SET NULL ON UPDATE CASCADE;
