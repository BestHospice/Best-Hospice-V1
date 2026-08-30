-- Remove legacy account fields now handled by ProviderUser
ALTER TABLE "Provider"
  DROP COLUMN IF EXISTS "accountEmail",
  DROP COLUMN IF EXISTS "accountPasswordHash",
  DROP COLUMN IF EXISTS "accountEmailVerified";
