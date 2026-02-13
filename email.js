const sgMail = require('@sendgrid/mail');

function emailEnabled() {
  return Boolean(process.env.SENDGRID_API_KEY && process.env.SENDGRID_FROM_EMAIL);
}

function initSendGrid() {
  if (!emailEnabled()) return false;
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  return true;
}

function buildEmailHtml({ clientZip, requestSubmittedBy, careDaysAndTimes, services, funding, otherDetails, clientEmail, clientPhone, clientName }) {
  const servicesList = Array.isArray(services) && services.length
    ? services.map((s) => `<li>${s}</li>`).join('')
    : '<li>Not specified</li>';
  const emailLine = clientEmail && clientEmail !== 'Not provided'
    ? `<a href="mailto:${clientEmail}">${clientEmail}</a>`
    : 'Not provided';
  const phoneLine = clientPhone && clientPhone !== 'Not provided' ? clientPhone : 'Not provided';
  const nameLine = clientName && clientName !== 'Not provided' ? clientName : 'Not provided';
  const fundingLine = funding && funding !== 'Not specified' ? funding : 'Not specified';
  const detailsLine = otherDetails && otherDetails !== 'Not provided' ? otherDetails : 'Not provided';

  return `
<div style="font-family: Arial, Helvetica, sans-serif; line-height: 1.6; color: #222;">
  <p><strong>Best Hospice and Home Health</strong> is your trusted partner in connecting you with clients in need nearby.</p>
  <p>
    We have identified a client located in <strong>Zip Code ${clientZip}</strong> with the following care request:
  </p>
  <hr />
  <p>
    <strong>Request Submitted By:</strong> ${requestSubmittedBy}
  </p>
  <p>
    <strong>Care Schedule Needed:</strong> ${careDaysAndTimes}
  </p>
  <p>
    <strong>Requested Services:</strong>
  </p>
  <ul>
    ${servicesList}
  </ul>
  <p>
    <strong>Funding:</strong> ${fundingLine}
  </p>
  <p>
    <strong>Other notes:</strong> ${detailsLine}
  </p>
  <p>
    <strong>Client Contact Information:</strong><br />
    Name: ${nameLine}<br />
    Email: ${emailLine}<br />
    Phone: ${phoneLine}
  </p>
  <hr />
  <p>
    We support care that acts quickly at <strong>Best Hospice and Home Health</strong>.  
    We encourage you to reach out promptly!
  </p>
  <p>
    Thank you for being a valued member of <strong>Best Hospice and Home Health</strong> and for providing compassionate care during life’s most difficult moments.
  </p>
  <br />
  <p>
    Have a blessed day,<br />
    <strong>Best Hospice and Home Health Team</strong><br />
    <a href="mailto:admin@besthospice.com">admin@besthospice.com</a>
  </p>
  <p style="font-style: italic; color: #555;">
    “Because your loved ones deserve the best, period.”
  </p>
  <hr />
  <p style="font-size: 12px; color: #777;">
    This message was sent via BestHospice.com as part of a care-coordination referral.  
    Please handle all client information in accordance with applicable privacy and professional standards.
  </p>
  <p style="font-size: 12px; color: #777;">
    This message contains confidential referral information.
  </p>
</div>
`;
}

async function sendProviderNotifications({ clientZip, requestSubmittedBy, careDaysAndTimes, services, funding, otherDetails, clientEmail, clientPhone, clientName, providers }) {
  if (!initSendGrid()) {
    throw new Error('SendGrid not configured');
  }
  const from = process.env.SENDGRID_FROM_EMAIL;
  const replyTo = process.env.SENDGRID_REPLY_TO || from;
  const subject = `Best Hospice and Home Health New Client Notification – Zip Code ${clientZip}`;

  const results = [];
  for (const provider of providers) {
    if (!provider.email) continue;
    const html = buildEmailHtml({
      clientZip,
      requestSubmittedBy,
      careDaysAndTimes,
      services,
      funding,
      otherDetails,
      clientEmail,
      clientPhone,
      clientName
    });

    const msg = {
      to: provider.email,
      from,
      replyTo,
      subject,
      html
    };

    try {
      const [resp] = await sgMail.send(msg);
      const messageId = resp?.headers?.['x-message-id'] || resp?.headers?.['X-Message-Id'];
      results.push({ email: provider.email, providerId: provider.id, status: 'sent', messageId });
    } catch (error) {
      console.error('SendGrid send failed for', provider.email, error?.response?.body || error);
      results.push({ email: provider.email, providerId: provider.id, status: 'failed', error: error.message || 'unknown error' });
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
