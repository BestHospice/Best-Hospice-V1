-- CreateTable
CREATE TABLE "CmsRelease" (
    "id" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "releaseKey" TEXT NOT NULL,
    "capturedAt" TIMESTAMP(3) NOT NULL,
    "ingestedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "datasetCount" INTEGER NOT NULL,
    "manifestSha256" TEXT,

    CONSTRAINT "CmsRelease_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CmsFacility" (
    "id" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "ccn" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "address" TEXT NOT NULL,
    "city" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "zip" TEXT NOT NULL,
    "county" TEXT,
    "phone" TEXT,
    "ownershipType" TEXT,
    "certificationDate" DATE,
    "firstSeenReleaseId" TEXT NOT NULL,
    "lastSeenReleaseId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CmsFacility_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CmsFacilityServiceArea" (
    "id" TEXT NOT NULL,
    "facilityId" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "zip" TEXT NOT NULL,
    "firstSeenReleaseId" TEXT NOT NULL,
    "lastSeenReleaseId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CmsFacilityServiceArea_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "CmsRelease_source_releaseKey_key" ON "CmsRelease"("source", "releaseKey");

-- CreateIndex
CREATE UNIQUE INDEX "CmsRelease_id_source_key" ON "CmsRelease"("id", "source");

-- CreateIndex
CREATE INDEX "CmsFacility_source_state_idx" ON "CmsFacility"("source", "state");

-- CreateIndex
CREATE INDEX "CmsFacility_source_zip_idx" ON "CmsFacility"("source", "zip");

-- CreateIndex
CREATE INDEX "CmsFacility_firstSeenReleaseId_idx" ON "CmsFacility"("firstSeenReleaseId");

-- CreateIndex
CREATE INDEX "CmsFacility_lastSeenReleaseId_idx" ON "CmsFacility"("lastSeenReleaseId");

-- CreateIndex
CREATE UNIQUE INDEX "CmsFacility_source_ccn_key" ON "CmsFacility"("source", "ccn");

-- CreateIndex
CREATE UNIQUE INDEX "CmsFacility_id_source_key" ON "CmsFacility"("id", "source");

-- CreateIndex
CREATE INDEX "CmsFacilityServiceArea_source_zip_idx" ON "CmsFacilityServiceArea"("source", "zip");

-- CreateIndex
CREATE INDEX "CmsFacilityServiceArea_lastSeenReleaseId_idx" ON "CmsFacilityServiceArea"("lastSeenReleaseId");

-- CreateIndex
CREATE UNIQUE INDEX "CmsFacilityServiceArea_facilityId_zip_key" ON "CmsFacilityServiceArea"("facilityId", "zip");

-- AddForeignKey
ALTER TABLE "CmsFacility" ADD CONSTRAINT "CmsFacility_firstSeenReleaseId_source_fkey" FOREIGN KEY ("firstSeenReleaseId", "source") REFERENCES "CmsRelease"("id", "source") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CmsFacility" ADD CONSTRAINT "CmsFacility_lastSeenReleaseId_source_fkey" FOREIGN KEY ("lastSeenReleaseId", "source") REFERENCES "CmsRelease"("id", "source") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CmsFacilityServiceArea" ADD CONSTRAINT "CmsFacilityServiceArea_facilityId_source_fkey" FOREIGN KEY ("facilityId", "source") REFERENCES "CmsFacility"("id", "source") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CmsFacilityServiceArea" ADD CONSTRAINT "CmsFacilityServiceArea_firstSeenReleaseId_source_fkey" FOREIGN KEY ("firstSeenReleaseId", "source") REFERENCES "CmsRelease"("id", "source") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CmsFacilityServiceArea" ADD CONSTRAINT "CmsFacilityServiceArea_lastSeenReleaseId_source_fkey" FOREIGN KEY ("lastSeenReleaseId", "source") REFERENCES "CmsRelease"("id", "source") ON DELETE RESTRICT ON UPDATE CASCADE;
