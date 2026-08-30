-- Add careType to providers
ALTER TABLE "Provider" ADD COLUMN "careType" TEXT NOT NULL DEFAULT 'hospice';
