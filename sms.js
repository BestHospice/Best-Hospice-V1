const twilio = require('twilio');
let smsDisabledUntilConfigFix = false;

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
  if (smsDisabledUntilConfigFix) {
    return { status: 'skipped', reason: 'sms_temporarily_disabled_until_config_fix' };
  }
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
    const message = String(err?.message || 'unknown error');
    const mismatch = message.toLowerCase().includes("mismatch between the 'from' number");
    if (mismatch) {
      smsDisabledUntilConfigFix = true;
      console.error('SMS disabled until config fix: TWILIO_FROM_NUMBER does not match current TWILIO_ACCOUNT_SID.');
      return { status: 'failed', error: message, permanentFailure: true };
    }
    console.error('SMS send failed', message);
    return { status: 'failed', error: message };
  }
}

module.exports = { sendProviderSms, smsEnabled };
