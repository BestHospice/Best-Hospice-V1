-- CreateTable
CREATE TABLE "LeadOutcome" (
    "id" TEXT NOT NULL,
    "leadId" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'new',
    "firstResponseAt" TIMESTAMP(3),
    "lastStatusChangedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "LeadOutcome_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "LeadOutcomeEvent" (
    "id" TEXT NOT NULL,
    "leadOutcomeId" TEXT NOT NULL,
    "fromStatus" TEXT,
    "toStatus" TEXT NOT NULL,
    "changedBy" TEXT NOT NULL DEFAULT 'provider',
    "changedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "LeadOutcomeEvent_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE UNIQUE INDEX "LeadOutcome_leadId_providerId_key" ON "LeadOutcome"("leadId", "providerId");

-- CreateIndex
CREATE INDEX "LeadOutcome_providerId_status_idx" ON "LeadOutcome"("providerId", "status");

-- CreateIndex
CREATE INDEX "LeadOutcome_leadId_idx" ON "LeadOutcome"("leadId");

-- CreateIndex
CREATE INDEX "LeadOutcomeEvent_leadOutcomeId_changedAt_idx" ON "LeadOutcomeEvent"("leadOutcomeId", "changedAt");

-- AddForeignKey
ALTER TABLE "LeadOutcome" ADD CONSTRAINT "LeadOutcome_leadId_fkey" FOREIGN KEY ("leadId") REFERENCES "Lead"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LeadOutcome" ADD CONSTRAINT "LeadOutcome_providerId_fkey" FOREIGN KEY ("providerId") REFERENCES "Provider"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LeadOutcomeEvent" ADD CONSTRAINT "LeadOutcomeEvent_leadOutcomeId_fkey" FOREIGN KEY ("leadOutcomeId") REFERENCES "LeadOutcome"("id") ON DELETE RESTRICT ON UPDATE CASCADE;
