const twilio = require('twilio');

function smsEnabled() {
  return (
    process.env.TWILIO_ACCOUNT_SID &&
    process.env.TWILIO_AUTH_TOKEN &&
    process.env.TWILIO_FROM_NUMBER
  );
}

function getClient() {
  if (!smsEnabled()) return null;
  return twilio(process.env.TWILIO_ACCOUNT_SID, process.env.TWILIO_AUTH_TOKEN);
}

async function sendProviderSms(to, body) {
  const client = getClient();
  if (!client) return { status: 'skipped', reason: 'sms_not_configured' };
  try {
    const msg = await client.messages.create({
      from: process.env.TWILIO_FROM_NUMBER,
      to,
      body
    });
    return { status: 'sent', sid: msg.sid };
  } catch (err) {
    console.error('SMS send failed', err?.message || err);
    return { status: 'failed', error: err?.message || 'unknown error' };
  }
}

module.exports = { sendProviderSms, smsEnabled };
