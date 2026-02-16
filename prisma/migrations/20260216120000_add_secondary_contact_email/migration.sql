-- Add optional second client contact email for provider lead routing
ALTER TABLE "Provider" ADD COLUMN "secondaryContactEmail" TEXT;
