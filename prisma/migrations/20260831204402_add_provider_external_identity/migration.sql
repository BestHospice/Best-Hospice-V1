-- CreateTable
CREATE TABLE "ProviderExternalIdentity" (
    "id" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "externalId" TEXT NOT NULL,
    "identifierType" TEXT,
    "confidence" DOUBLE PRECISION,
    "verifiedAt" TIMESTAMP(3),
    "verifiedBy" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "ProviderExternalIdentity_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "ProviderExternalIdentity_providerId_idx" ON "ProviderExternalIdentity"("providerId");

-- CreateIndex
CREATE INDEX "ProviderExternalIdentity_source_idx" ON "ProviderExternalIdentity"("source");

-- CreateIndex
CREATE UNIQUE INDEX "ProviderExternalIdentity_source_externalId_key" ON "ProviderExternalIdentity"("source", "externalId");

-- AddForeignKey
ALTER TABLE "ProviderExternalIdentity" ADD CONSTRAINT "ProviderExternalIdentity_providerId_fkey" FOREIGN KEY ("providerId") REFERENCES "Provider"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
