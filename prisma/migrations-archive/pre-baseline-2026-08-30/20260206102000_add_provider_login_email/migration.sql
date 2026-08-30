-- Add provider login email for dashboard access
ALTER TABLE "Provider" ADD COLUMN "providerLoginEmail" TEXT;

-- Default login email to client contact email for existing providers
UPDATE "Provider" SET "providerLoginEmail" = "email" WHERE "providerLoginEmail" IS NULL;
