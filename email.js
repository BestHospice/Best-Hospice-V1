const sgMail = require('@sendgrid/mail');

function emailEnabled() {
  return Boolean(process.env.SENDGRID_API_KEY && process.env.SENDGRID_FROM_EMAIL);
}

function initSendGrid() {
  if (!emailEnabled()) return false;
  sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  return true;
}

function buildEmailHtml({ clientZip, requestSubmittedBy, careDaysAndTimes, services, clientEmail, clientPhone, clientName, nearbyProviders }) {
  const servicesList = Array.isArray(services) && services.length
    ? services.map((s) => `<li>${s}</li>`).join('')
    : '<li>Not specified</li>';
  const nearbyList = Array.isArray(nearbyProviders) && nearbyProviders.length
    ? nearbyProviders.map((p) => `<li>${p.name}${p.address ? ` — ${p.address}` : ''}</li>`).join('')
    : '<li>No other providers listed</li>';
  const emailLine = clientEmail && clientEmail !== 'Not provided'
    ? `<a href="mailto:${clientEmail}">${clientEmail}</a>`
    : 'Not provided';
  const phoneLine = clientPhone && clientPhone !== 'Not provided' ? clientPhone : 'Not provided';
  const nameLine = clientName && clientName !== 'Not provided' ? clientName : 'Not provided';

  return `
<div style="font-family: Arial, Helvetica, sans-serif; line-height: 1.6; color: #222;">
  <p><strong>Best Hospice</strong> is your trusted partner in connecting you with clients in need nearby.</p>
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
    <strong>Client Contact Information:</strong><br />
    Name: ${nameLine}<br />
    Email: ${emailLine}<br />
    Phone: ${phoneLine}
  </p>
  <hr />
  <p>
    We support care that acts quickly at <strong>Best Hospice</strong>.  
    We encourage you to reach out promptly, as other hospice providers in your area have also been notified:
  </p>
  <ul>
    ${nearbyList}
  </ul>
  <p>
    Thank you for being a valued member of <strong>Best Hospice</strong> and for providing compassionate care during life’s most difficult moments.
  </p>
  <br />
  <p>
    Have a blessed day,<br />
    <strong>Best Hospice Team</strong><br />
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
</div>
`;
}

async function sendProviderNotifications({ clientZip, requestSubmittedBy, careDaysAndTimes, services, clientEmail, clientPhone, clientName, providers, nearbyProviders }) {
  if (!initSendGrid()) {
    throw new Error('SendGrid not configured');
  }
  const from = process.env.SENDGRID_FROM_EMAIL;
  const replyTo = process.env.SENDGRID_REPLY_TO || from;
  const subject = `Best Hospice New Client Notification – Zip Code ${clientZip}`;

  const results = [];
  for (const provider of providers) {
    if (!provider.email) continue;
    const others = (nearbyProviders || []).filter((p) => p.email !== provider.email);
    const html = buildEmailHtml({
      clientZip,
      requestSubmittedBy,
      careDaysAndTimes,
      services,
      clientEmail,
      clientPhone,
      clientName,
      nearbyProviders: others
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

async function sendTestEmail(to) {
  if (!initSendGrid()) throw new Error('SendGrid not configured');
  const msg = {
    to,
    from: process.env.SENDGRID_FROM_EMAIL,
    replyTo: process.env.SENDGRID_REPLY_TO || process.env.SENDGRID_FROM_EMAIL,
    subject: 'Best Hospice test email',
    html: '<p>This is a test email from Best Hospice backend.</p>'
  };
  await sgMail.send(msg);
}

module.exports = { sendProviderNotifications, sendTestEmail, emailEnabled };
