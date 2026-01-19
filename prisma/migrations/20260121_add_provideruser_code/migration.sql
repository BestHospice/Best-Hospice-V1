-- Add one-time signup code fields to ProviderUser
ALTER TABLE "ProviderUser"
  ADD COLUMN "verifyCode" TEXT,
  ADD COLUMN "verifyCodeExpiresAt" TIMESTAMP(3);
