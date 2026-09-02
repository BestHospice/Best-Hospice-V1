-- CreateTable
CREATE TABLE "CmsMeasureDefinition" (
    "id" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "measureCode" TEXT NOT NULL,
    "cmsMeasureName" TEXT NOT NULL,
    "shortLabel" TEXT NOT NULL,
    "dimension" TEXT NOT NULL,
    "family" TEXT NOT NULL,
    "valueKind" TEXT NOT NULL,
    "direction" TEXT NOT NULL,
    "scaleMin" DOUBLE PRECISION,
    "scaleMax" DOUBLE PRECISION,
    "decimals" INTEGER NOT NULL,
    "unitLabel" TEXT,
    "denominatorCode" TEXT,
    "surfaced" BOOLEAN NOT NULL DEFAULT false,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CmsMeasureDefinition_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "CmsFacilityMeasure" (
    "id" TEXT NOT NULL,
    "facilityId" TEXT NOT NULL,
    "source" TEXT NOT NULL,
    "measureCode" TEXT NOT NULL,
    "releaseId" TEXT NOT NULL,
    "valueNumeric" DOUBLE PRECISION,
    "valueRaw" TEXT NOT NULL,
    "suppressed" BOOLEAN NOT NULL,
    "footnoteCodes" TEXT[],
    "denominator" DOUBLE PRECISION,
    "starRating" INTEGER,
    "periodStart" DATE,
    "periodEnd" DATE,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "CmsFacilityMeasure_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "CmsMeasureDefinition_source_surfaced_idx" ON "CmsMeasureDefinition"("source", "surfaced");

-- CreateIndex
CREATE UNIQUE INDEX "CmsMeasureDefinition_source_measureCode_key" ON "CmsMeasureDefinition"("source", "measureCode");

-- CreateIndex
CREATE UNIQUE INDEX "CmsMeasureDefinition_id_source_key" ON "CmsMeasureDefinition"("id", "source");

-- CreateIndex
CREATE INDEX "CmsFacilityMeasure_source_releaseId_measureCode_facilityId_idx" ON "CmsFacilityMeasure"("source", "releaseId", "measureCode", "facilityId");

-- CreateIndex
CREATE INDEX "CmsFacilityMeasure_facilityId_releaseId_idx" ON "CmsFacilityMeasure"("facilityId", "releaseId");

-- CreateIndex
CREATE INDEX "CmsFacilityMeasure_releaseId_idx" ON "CmsFacilityMeasure"("releaseId");

-- CreateIndex
CREATE UNIQUE INDEX "CmsFacilityMeasure_facilityId_measureCode_releaseId_key" ON "CmsFacilityMeasure"("facilityId", "measureCode", "releaseId");

-- AddForeignKey
ALTER TABLE "CmsFacilityMeasure" ADD CONSTRAINT "CmsFacilityMeasure_facilityId_source_fkey" FOREIGN KEY ("facilityId", "source") REFERENCES "CmsFacility"("id", "source") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CmsFacilityMeasure" ADD CONSTRAINT "CmsFacilityMeasure_releaseId_source_fkey" FOREIGN KEY ("releaseId", "source") REFERENCES "CmsRelease"("id", "source") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "CmsFacilityMeasure" ADD CONSTRAINT "CmsFacilityMeasure_source_measureCode_fkey" FOREIGN KEY ("source", "measureCode") REFERENCES "CmsMeasureDefinition"("source", "measureCode") ON DELETE RESTRICT ON UPDATE CASCADE;

