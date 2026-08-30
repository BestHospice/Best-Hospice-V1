-- CreateTable
CREATE TABLE "Provider" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "phone" TEXT,
    "website" TEXT,
    "address" TEXT NOT NULL,
    "city" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "zip" TEXT NOT NULL,
    "lat" DOUBLE PRECISION NOT NULL,
    "lon" DOUBLE PRECISION NOT NULL,
    "serviceRadiusKm" DOUBLE PRECISION NOT NULL,
    "featured" BOOLEAN NOT NULL DEFAULT false,
    "leadCount" INTEGER NOT NULL DEFAULT 0,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    "planTier" TEXT NOT NULL DEFAULT 'verified',
    "providerLoginEmail" TEXT,
    "careType" TEXT NOT NULL DEFAULT 'hospice',
    "secondaryContactEmail" TEXT,
    "serviceZipCodes" TEXT,
    "activelyHiring" BOOLEAN NOT NULL DEFAULT true,
    "receiveClientLeads" BOOLEAN NOT NULL DEFAULT true,
    "receiveJobLeads" BOOLEAN NOT NULL DEFAULT true,
    "stripeCustomerId" TEXT,
    "stripeSubscriptionId" TEXT,
    "subscriptionStatus" TEXT,
    "currentPeriodEnd" TIMESTAMP(6),
    "billingMode" TEXT NOT NULL DEFAULT 'free',
    "subscriptionMonthlyCents" INTEGER,

    CONSTRAINT "Provider_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Lead" (
    "id" TEXT NOT NULL,
    "zip" TEXT NOT NULL,
    "submittedBy" TEXT NOT NULL,
    "careDays" TEXT,
    "careTimes" TEXT,
    "services" TEXT,
    "clientEmail" TEXT,
    "clientPhone" TEXT,
    "firstName" TEXT,
    "lastName" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "sessionId" TEXT,
    "adminStatus" TEXT,
    "adminProviderId" TEXT,
    "gclid" TEXT,
    "fbclid" TEXT,
    "firstChannel" TEXT,
    "firstSource" TEXT,
    "firstMedium" TEXT,
    "firstCampaign" TEXT,
    "firstTerm" TEXT,
    "firstContent" TEXT,
    "firstLandingPage" TEXT,
    "firstReferrer" TEXT,
    "firstTouchAt" TIMESTAMPTZ(6),
    "lastChannel" TEXT,
    "lastSource" TEXT,
    "lastMedium" TEXT,
    "lastCampaign" TEXT,
    "lastTerm" TEXT,
    "lastContent" TEXT,
    "lastLandingPage" TEXT,
    "lastReferrer" TEXT,
    "lastTouchAt" TIMESTAMPTZ(6),

    CONSTRAINT "Lead_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "LeadNotification" (
    "id" TEXT NOT NULL,
    "leadId" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "status" TEXT NOT NULL,
    "sendgridMessageId" TEXT,
    "errorMessage" TEXT,
    "sentAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "LeadNotification_pkey" PRIMARY KEY ("id")
);

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

-- CreateTable
CREATE TABLE "NotificationJob" (
    "id" TEXT NOT NULL,
    "leadId" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "runAt" TIMESTAMP(3) NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "lastError" TEXT,
    "lockedAt" TIMESTAMP(3),
    "payload" JSONB NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,

    CONSTRAINT "NotificationJob_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ProviderImpression" (
    "id" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "leadId" TEXT,
    "zip" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ProviderImpression_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BlogPost" (
    "id" TEXT NOT NULL,
    "title" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "authorEmail" TEXT NOT NULL,
    "authorCity" TEXT NOT NULL,
    "authorState" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BlogPost_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BlogComment" (
    "id" TEXT NOT NULL,
    "postId" TEXT NOT NULL,
    "body" TEXT NOT NULL,
    "authorEmail" TEXT NOT NULL,
    "authorCity" TEXT NOT NULL,
    "authorState" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BlogComment_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "BlogEmailVerification" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "city" TEXT NOT NULL,
    "state" TEXT NOT NULL,
    "code" TEXT NOT NULL,
    "expiresAt" TIMESTAMP(3) NOT NULL,
    "verifiedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "BlogEmailVerification_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "AdminAuditLog" (
    "id" TEXT NOT NULL,
    "adminIdentifier" TEXT NOT NULL,
    "action" TEXT NOT NULL,
    "targetType" TEXT NOT NULL,
    "targetId" TEXT,
    "metadataJson" TEXT,
    "ipHash" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "AdminAuditLog_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "RateLimitEvent" (
    "id" TEXT NOT NULL,
    "ipHash" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "RateLimitEvent_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ProviderUser" (
    "id" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "passwordHash" TEXT NOT NULL,
    "emailVerifiedAt" TIMESTAMP(3),
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "verifyCode" TEXT,
    "verifyCodeExpiresAt" TIMESTAMP(3),
    "activeProviderId" TEXT,

    CONSTRAINT "ProviderUser_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "ProviderUserProvider" (
    "id" TEXT NOT NULL,
    "providerUserId" TEXT NOT NULL,
    "providerId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "ProviderUserProvider_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "WaitlistRequest" (
    "id" TEXT NOT NULL,
    "zip" TEXT NOT NULL,
    "contactEmail" TEXT,
    "contactPhone" TEXT,
    "timeline" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "WaitlistRequest_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "JobLead" (
    "id" TEXT NOT NULL,
    "zip" TEXT NOT NULL,
    "name" TEXT,
    "email" TEXT,
    "phone" TEXT,
    "role" TEXT,
    "licensed" TEXT,
    "availability" TEXT,
    "timeline" TEXT,
    "experience" TEXT,
    "openToMultiple" TEXT,
    "notifiedProviderIds" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "JobLead_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "DischargeReferral" (
    "id" TEXT NOT NULL,
    "planner_name" TEXT,
    "planner_title" TEXT,
    "planner_email" TEXT,
    "planner_phone" TEXT,
    "facility" TEXT,
    "patient_first" TEXT,
    "patient_last" TEXT,
    "patient_zip" TEXT,
    "care_type" TEXT,
    "urgency" TEXT,
    "insurance" TEXT,
    "notes" TEXT,
    "status" TEXT NOT NULL DEFAULT 'new',
    "source" TEXT NOT NULL DEFAULT 'discharge_planner',
    "submitted_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "DischargeReferral_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "Testimonial" (
    "id" TEXT NOT NULL,
    "quote" TEXT NOT NULL,
    "author_name" TEXT NOT NULL,
    "author_title" TEXT,
    "active" BOOLEAN NOT NULL DEFAULT true,
    "display_order" INTEGER NOT NULL DEFAULT 0,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "status" TEXT NOT NULL DEFAULT 'approved',
    "provider_id" TEXT,
    "reviewed_at" TIMESTAMPTZ(6),

    CONSTRAINT "Testimonial_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "newsletter_issues" (
    "id" TEXT NOT NULL,
    "issue_number" INTEGER NOT NULL,
    "slug" TEXT NOT NULL,
    "subject" TEXT NOT NULL,
    "preview" TEXT,
    "web_html" TEXT,
    "sent_count" INTEGER NOT NULL DEFAULT 0,
    "failed_count" INTEGER NOT NULL DEFAULT 0,
    "sent_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "newsletter_issues_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "newsletter_subscribers" (
    "id" TEXT NOT NULL,
    "name" TEXT NOT NULL,
    "email" TEXT NOT NULL,
    "source" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "newsletter_subscribers_pkey" PRIMARY KEY ("id")
);

-- CreateTable
CREATE TABLE "website_events" (
    "id" TEXT NOT NULL,
    "viewer_id" TEXT NOT NULL,
    "session_id" TEXT NOT NULL,
    "event_type" TEXT NOT NULL,
    "path" TEXT NOT NULL,
    "referrer" TEXT,
    "duration_ms" INTEGER,
    "scroll_depth" INTEGER,
    "event_value" TEXT,
    "metadata_json" TEXT,
    "user_agent" TEXT,
    "ip_hash" TEXT,
    "created_at" TIMESTAMPTZ(6) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "website_events_pkey" PRIMARY KEY ("id")
);

-- CreateIndex
CREATE INDEX "idx_lead_first_channel" ON "Lead"("firstChannel");

-- CreateIndex
CREATE INDEX "idx_lead_session_id" ON "Lead"("sessionId");

-- CreateIndex
CREATE INDEX "LeadOutcome_providerId_status_idx" ON "LeadOutcome"("providerId", "status");

-- CreateIndex
CREATE INDEX "LeadOutcome_leadId_idx" ON "LeadOutcome"("leadId");

-- CreateIndex
CREATE UNIQUE INDEX "LeadOutcome_leadId_providerId_key" ON "LeadOutcome"("leadId", "providerId");

-- CreateIndex
CREATE INDEX "LeadOutcomeEvent_leadOutcomeId_changedAt_idx" ON "LeadOutcomeEvent"("leadOutcomeId", "changedAt");

-- CreateIndex
CREATE INDEX "NotificationJob_status_runAt_idx" ON "NotificationJob"("status", "runAt");

-- CreateIndex
CREATE INDEX "NotificationJob_lockedAt_idx" ON "NotificationJob"("lockedAt");

-- CreateIndex
CREATE INDEX "NotificationJob_providerId_idx" ON "NotificationJob"("providerId");

-- CreateIndex
CREATE INDEX "NotificationJob_leadId_idx" ON "NotificationJob"("leadId");

-- CreateIndex
CREATE INDEX "BlogEmailVerification_email_code_idx" ON "BlogEmailVerification"("email", "code");

-- CreateIndex
CREATE INDEX "BlogEmailVerification_email_verifiedAt_idx" ON "BlogEmailVerification"("email", "verifiedAt");

-- CreateIndex
CREATE UNIQUE INDEX "ProviderUser_email_key" ON "ProviderUser"("email");

-- CreateIndex
CREATE UNIQUE INDEX "ProviderUserProvider_providerUserId_providerId_key" ON "ProviderUserProvider"("providerUserId", "providerId");

-- CreateIndex
CREATE UNIQUE INDEX "idx_newsletter_issues_slug" ON "newsletter_issues"("slug");

-- CreateIndex
CREATE UNIQUE INDEX "newsletter_subscribers_email_key" ON "newsletter_subscribers"("email");

-- CreateIndex
CREATE INDEX "idx_newsletter_subscribers_email" ON "newsletter_subscribers"("email");

-- CreateIndex
CREATE INDEX "idx_website_events_created_at" ON "website_events"("created_at");

-- CreateIndex
CREATE INDEX "idx_website_events_event_type" ON "website_events"("event_type");

-- CreateIndex
CREATE INDEX "idx_website_events_session_id" ON "website_events"("session_id");

-- CreateIndex
CREATE INDEX "idx_website_events_viewer_id" ON "website_events"("viewer_id");

-- AddForeignKey
ALTER TABLE "LeadNotification" ADD CONSTRAINT "LeadNotification_leadId_fkey" FOREIGN KEY ("leadId") REFERENCES "Lead"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LeadNotification" ADD CONSTRAINT "LeadNotification_providerId_fkey" FOREIGN KEY ("providerId") REFERENCES "Provider"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LeadOutcome" ADD CONSTRAINT "LeadOutcome_leadId_fkey" FOREIGN KEY ("leadId") REFERENCES "Lead"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LeadOutcome" ADD CONSTRAINT "LeadOutcome_providerId_fkey" FOREIGN KEY ("providerId") REFERENCES "Provider"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "LeadOutcomeEvent" ADD CONSTRAINT "LeadOutcomeEvent_leadOutcomeId_fkey" FOREIGN KEY ("leadOutcomeId") REFERENCES "LeadOutcome"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ProviderImpression" ADD CONSTRAINT "ProviderImpression_leadId_fkey" FOREIGN KEY ("leadId") REFERENCES "Lead"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ProviderImpression" ADD CONSTRAINT "ProviderImpression_providerId_fkey" FOREIGN KEY ("providerId") REFERENCES "Provider"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "BlogComment" ADD CONSTRAINT "BlogComment_postId_fkey" FOREIGN KEY ("postId") REFERENCES "BlogPost"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ProviderUser" ADD CONSTRAINT "ProviderUser_activeProviderId_fkey" FOREIGN KEY ("activeProviderId") REFERENCES "Provider"("id") ON DELETE SET NULL ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ProviderUserProvider" ADD CONSTRAINT "ProviderUserProvider_providerId_fkey" FOREIGN KEY ("providerId") REFERENCES "Provider"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "ProviderUserProvider" ADD CONSTRAINT "ProviderUserProvider_providerUserId_fkey" FOREIGN KEY ("providerUserId") REFERENCES "ProviderUser"("id") ON DELETE RESTRICT ON UPDATE CASCADE;

