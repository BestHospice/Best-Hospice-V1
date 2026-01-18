-- AlterTable
ALTER TABLE "Provider" ADD COLUMN     "accountEmail" TEXT,
ADD COLUMN     "accountEmailVerified" BOOLEAN NOT NULL DEFAULT false,
ADD COLUMN     "accountPasswordHash" TEXT;
