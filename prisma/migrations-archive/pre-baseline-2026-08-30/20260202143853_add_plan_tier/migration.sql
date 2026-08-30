-- DropForeignKey
ALTER TABLE "ProviderUserProvider" DROP CONSTRAINT "ProviderUserProvider_providerId_fkey";

-- DropForeignKey
ALTER TABLE "ProviderUserProvider" DROP CONSTRAINT "ProviderUserProvider_providerUserId_fkey";

-- AlterTable
ALTER TABLE "Provider" ADD COLUMN     "planTier" TEXT NOT NULL DEFAULT 'starter';

-- AddForeignKey
ALTER TABLE "ProviderUserProvider" ADD CONSTRAINT "ProviderUserProvider_providerUserId_fkey" FOREIGN KEY ("providerUserId") REFERENCES "ProviderUser"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ProviderUserProvider" ADD CONSTRAINT "ProviderUserProvider_providerId_fkey" FOREIGN KEY ("providerId") REFERENCES "Provider"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
