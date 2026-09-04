-- CreateTable
CREATE TABLE "CmsFacilityObservation" (
    "id" TEXT NOT NULL,
    "facilityId" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "releaseId" TEXT NOT NULL,
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
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "CmsFacilityObservation_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "CmsFacilityObservation_source_releaseId_idx" ON "CmsFacilityObservation"("source", "releaseId");

-- CreateIndex
CREATE INDEX "CmsFacilityObservation_source_releaseId_ownershipType_idx" ON "CmsFacilityObservation"("source", "releaseId", "ownershipType");

-- CreateIndex
CREATE UNIQUE INDEX "CmsFacilityObservation_facilityId_releaseId_key" ON "CmsFacilityObservation"("facilityId", "releaseId");

-- AddForeignKey
ALTER TABLE "CmsFacilityObservation" ADD CONSTRAINT "CmsFacilityObservation_facilityId_source_fkey" FOREIGN KEY ("facilityId", "source") REFERENCES "CmsFacility"("id", "source") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CmsFacilityObservation" ADD CONSTRAINT "CmsFacilityObservation_releaseId_source_fkey" FOREIGN KEY ("releaseId", "source") REFERENCES "CmsRelease"("id", "source") ON DELETE RESTRICT ON UPDATE CASCADE;
