const sgMail = require('@sendgrid/mail');

function emailEnabled() {
  return Boolean(process.env.SENDGRID_API_KEY && process.env.SENDGRID_FROM_EMAIL);
}

function initSendGrid() {
  if (!emailEnabled()) return false;
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  return true;
}

function toDisplay(value, fallback = 'Not provided') {
  return String(value || '').trim() || fallback;
}

function sharedSignatureBlock() {
  return `
  <p>We support care that acts quickly at <strong>Best Hospice and Home Health</strong>. We encourage you to reach out promptly!</p>
  <p>Thank you for being a valued member of <strong>Best Hospice and Home Health</strong> and for providing compassionate care during life’s most difficult moments.</p>
  <br />
  <p>Have a blessed day,<br />
  <strong>Best Hospice and Home Health Team</strong><br />
  <a href="mailto:admin@besthospice.com">admin@besthospice.com</a></p>
  <p style="font-style: italic; color:#555;">“Because your loved ones deserve the best, period.”</p>
`;
}

function buildInitialLeadEmailHtml({ clientZip, timeline, clientEmail, clientPhone, providerCount }) {
  return `
<div style="font-family: Arial, Helvetica, sans-serif; line-height: 1.6; color: #222;">
  <p>A family in your service area is looking for care and has requested provider information.</p>
  <hr />
  <p><strong>CONTACT INFORMATION:</strong><br />
  Phone: ${toDisplay(clientPhone)}<br />
  Email: ${toDisplay(clientEmail)}<br />
  ZIP Code: ${toDisplay(clientZip)}<br />
  Timeline: ${toDisplay(timeline, 'Not specified')}</p>
  <p><strong>NEXT STEPS:</strong></p>
  <p>We recommend calling within 24 hours for best response rates. They are also contacting other providers, so prompt follow-up is important.</p>
  <p>View your lead dashboard: <a href="https://www.besthospice.com/provider-dashboard.html">Provider Dashboard</a></p>
  ${sharedSignatureBlock()}
  <hr />
  <p style="font-size:12px; color:#666;">This message contains confidential referral information.</p>
</div>
`;
}

function buildEnhancedLeadEmailHtml({
  clientZip,
  timeline,
  clientEmail,
  clientPhone,
  clientName,
  whoNeedsCare,
  careType,
  additionalNotes
}) {
  return `
<div style="font-family: Arial, Helvetica, sans-serif; line-height: 1.6; color: #222;">
  <p>The family from your earlier lead notification has provided additional details:</p>
  <hr />
  <p><strong>UPDATED INFORMATION:</strong><br />
  Name: ${toDisplay(clientName)}<br />
  Phone: ${toDisplay(clientPhone)}<br />
  Email: ${toDisplay(clientEmail)}<br />
  ZIP Code: ${toDisplay(clientZip)}<br />
  Timeline: ${toDisplay(timeline, 'Not specified')}</p>
  <p><strong>CARE DETAILS:</strong><br />
  Who needs care: ${toDisplay(whoNeedsCare, 'Not specified')}<br />
  Type of care needed: ${toDisplay(careType, 'Not specified')}<br />
  Additional notes: "${toDisplay(additionalNotes, 'None provided')}"</p>
  <p>This family has provided more specific information to help you prepare for your conversation. If you haven't already reached out, now is a great time to call.</p>
  ${sharedSignatureBlock()}
  <hr />
  <p style="font-size:12px; color:#666;">This message contains confidential referral information.</p>
</div>
`;
}

async function sendProviderNotifications({
  notificationType = 'initial',
  clientZip,
  timeline,
  requestSubmittedBy,
  careDaysAndTimes,
  services,
  funding,
  otherDetails,
  clientEmail,
  clientPhone,
  clientName,
  whoNeedsCare,
  careType,
  additionalNotes,
  providerCount,
  providers
}) {
  if (!initSendGrid()) {
    throw new Error('SendGrid not configured');
  }
  const from = process.env.SENDGRID_FROM_EMAIL;
  const replyTo = process.env.SENDGRID_REPLY_TO || from;
  const leadMonitorEmail = String(process.env.LEAD_EMAIL_MONITOR || 'contact@besthospice.com').trim();
  const finalTimeline = timeline || careDaysAndTimes || 'Not specified';
  const finalWhoNeedsCare = whoNeedsCare || requestSubmittedBy || 'Not specified';
  const finalCareType = careType || (Array.isArray(services) ? services.join(', ') : services) || 'Not specified';
  const finalNotes = additionalNotes || otherDetails || '';
  const subject = notificationType === 'details'
    ? `Updated Lead Details - ${clientZip} - Best Hospice and Home Health`
    : `New Lead in Your Area - ${clientZip} - Best Hospice and Home Health`;

  const results = [];
  for (const provider of providers) {
    const recipientEmails = Array.isArray(provider.emails)
      ? provider.emails.map((e) => String(e || '').trim()).filter(Boolean)
      : [String(provider.email || '').trim()].filter(Boolean);
    if (!recipientEmails.length) continue;
    const html = notificationType === 'details'
      ? buildEnhancedLeadEmailHtml({
          clientZip,
          timeline: finalTimeline,
          clientEmail,
          clientPhone,
          clientName,
          whoNeedsCare: finalWhoNeedsCare,
          careType: finalCareType,
          additionalNotes: finalNotes
        })
      : buildInitialLeadEmailHtml({
          clientZip,
          timeline: finalTimeline,
          clientEmail,
          clientPhone,
          providerCount
        });

    for (const recipient of recipientEmails) {
      const msg = {
        to: recipient,
        from,
        replyTo,
        subject,
        html
      };
      if (leadMonitorEmail && leadMonitorEmail.toLowerCase() !== String(recipient).toLowerCase()) {
        msg.bcc = leadMonitorEmail;
      }

      try {
        const [resp] = await sgMail.send(msg);
        const messageId = resp?.headers?.['x-message-id'] || resp?.headers?.['X-Message-Id'];
        results.push({ email: recipient, providerId: provider.id, status: 'sent', messageId });
      } catch (error) {
        console.error('SendGrid send failed for', recipient, error?.response?.body || error);
        results.push({ email: recipient, providerId: provider.id, status: 'failed', error: error.message || 'unknown error' });
      }
    }
  }

  return results;
}

async function sendGenericEmail(to, subject, html) {
  if (!initSendGrid()) throw new Error('SendGrid not configured');
  const msg = {
    to,
    from: process.env.SENDGRID_FROM_EMAIL,
    replyTo: process.env.SENDGRID_REPLY_TO || process.env.SENDGRID_FROM_EMAIL,
    subject,
    html
  };
  await sgMail.send(msg);
}

async function sendTestEmail(to) {
  return sendGenericEmail(to, 'Best Hospice and Home Health test email', '<p>This is a test email from Best Hospice and Home Health backend.</p>');
}

module.exports = { sendProviderNotifications, sendTestEmail, sendGenericEmail, emailEnabled };
