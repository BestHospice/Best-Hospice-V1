'use strict';
const crypto = require('crypto');
const normalize = (v) => String(v || '').trim().toLowerCase();
// ECMAScript String.trim whitespace, also used when checking stored emails.
const trimCharacters = ' \t\n\r\v\f\u00a0\u1680\u2000\u2001\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u2028\u2029\u202f\u205f\u3000\ufeff';
const result = (status, message, extra = {}) => ({ status, message, ...extra });

function createProviderEnrollment({ prisma, secret, hashPassword, now = () => new Date() }) {
  const key = crypto.createHmac('sha256', secret).update('provider-verification-v1').digest();
  const mac = (v) => crypto.createHmac('sha256', key).update(JSON.stringify(v)).digest('hex');
  const equal = (a, b) => typeof a === 'string' && /^[a-f0-9]{64}$/.test(a)
    && crypto.timingSafeEqual(Buffer.from(a, 'hex'), Buffer.from(b, 'hex'));
  const digest = (c, expires, code) => mac([c.v, c.accountId, c.providerId, c.purpose,
    c.nonce, c.emailDigest, expires.toISOString(), code]);
  async function transaction(fn) {
    for (let n = 0; n < 3; n++) {
      try { return await prisma.$transaction(fn, { isolationLevel: 'Serializable' }); }
      catch (e) { if (!['P2034', 'P2002'].includes(e.code) || n === 2) throw e; }
    }
  }
  async function account(tx, email) {
    // Detect normalized legacy collisions without silently creating a second account.
    const rows = await tx.$queryRaw`SELECT id FROM "ProviderUser" WHERE ${email} = lower(btrim(email, ${trimCharacters}))`;
    if (rows.length > 1) return { anomaly: true };
    const u = rows.length ? await tx.providerUser.findUnique({ where: { id: rows[0].id }, include: { links: true } }) : null;
    // Login uses an exact lookup of normalized input. Do not enroll an account
    // whose stored spelling would make that unchanged login path fail.
    return u && u.email !== email ? { anomaly: true } : u;
  }
  const validProvider = (p, email) => p && p.internalRole === null && normalize(p.providerLoginEmail)
    && normalize(p.providerLoginEmail) === email;
  const inert = (u) => !u.activeProviderId && !u.links.length;
  async function throttle(tx, email, kind, date) {
    const ipHash = 'enrollment:' + mac([kind, email]);
    const rows = await tx.rateLimitEvent.findMany({ where: { ipHash,
      createdAt: { gte: new Date(date.getTime() - 3600000) } }, orderBy: { createdAt: 'desc' } });
    if (rows.length >= (kind === 'start' ? 5 : 20)
      || (kind === 'start' && rows[0] && date - rows[0].createdAt < 60000)) return false;
    await tx.rateLimitEvent.create({ data: { id: crypto.randomUUID(), ipHash, createdAt: date } });
    return true;
  }
  async function startFlow({ providerId, providerEmail }, accountId = null) {
    const adding = accountId !== null;
    let email = normalize(providerEmail);
    if ((!adding && !email) || typeof providerId !== 'string') return result('invalid_request', 'Provider and email required.');
    return transaction(async (tx) => {
      const date = now();
      const authenticated = adding ? await tx.providerUser.findUnique({ where: { id: accountId }, include: { links: true } }) : null;
      if (adding && !authenticated?.emailVerifiedAt) return result('unauthorized', 'A verified account is required.');
      if (adding) email = normalize(authenticated.email);
      const p = await tx.provider.findUnique({ where: { id: providerId } });
      if (!validProvider(p, email)) return result('invalid_request', 'Select a valid provider and its configured login email.');
      let u = adding ? authenticated : await account(tx, email);
      if (u?.anomaly) return result('manual_review', 'Please contact support to review this account.');
      if (!adding && u?.emailVerifiedAt) return result('existing_account', 'An account already exists. Log in using your existing password and an associated location.');
      if (!adding && u && !inert(u)) return result('manual_review', 'Please contact support to review this account.');
      if (adding && u.links.some(l => l.providerId === providerId)) return result('already_associated', 'This location is already associated.');
      if (!await throttle(tx, adding ? 'account:' + accountId : email, 'start', date)) return result('rate_limited', 'Please wait before requesting another code.');
      if (!u) u = await tx.providerUser.create({ data: { id: crypto.randomUUID(), email, passwordHash: '' } });
      const code = crypto.randomInt(100000, 1000000).toString();
      const expires = new Date(date.getTime() + 20 * 60000);
      const c = { v: 1, accountId: u.id, providerId, purpose: adding ? 'add_location' : 'first_enrollment',
        nonce: crypto.randomBytes(24).toString('hex'), emailDigest: mac(['email', email]), failedAttempts: 0 };
      c.codeDigest = digest(c, expires, code);
      await tx.providerUser.update({ where: { id: u.id }, data: { verifyCode: JSON.stringify(c), verifyCodeExpiresAt: expires } });
      // Only the caller's email transport receives this transient plaintext value.
      return result('challenge_sent', 'Check your email. The code expires in 20 minutes.', { delivery: { email, code }, challengeId: c.nonce });
    });
  }
  async function completeFlow({ email: input, providerId, challengeId, code, password }, accountId = null) {
    const adding = accountId !== null;
    let email = normalize(input);
    if ((!adding && !email) || typeof providerId !== 'string' || typeof challengeId !== 'string'
      || typeof code !== 'string' || !/^\d{6}$/.test(code) || (!adding && (typeof password !== 'string' || password.length < 8)))
      return result('invalid_request', adding ? 'Enter the selected location and six-digit code.'
        : 'Enter the selected provider, six-digit code, and a password of at least 8 characters.');
    const passwordHash = adding ? null : await hashPassword(password);
    return transaction(async (tx) => {
      const date = now();
      const u = adding ? await tx.providerUser.findUnique({ where: { id: accountId }, include: { links: true } }) : await account(tx, email);
      const restart = () => result('restart_required', 'Request a new signup code.');
      if (adding && !u?.emailVerifiedAt) return result('unauthorized', 'A verified account is required.');
      if (!adding && (!u || u.anomaly || u.emailVerifiedAt || !inert(u))) return restart();
      if (adding) email = normalize(u.email);
      if (!await throttle(tx, adding ? 'account:' + accountId : email, 'complete', date)) return result('rate_limited', 'Too many attempts. Please try later.');
      const p = await tx.provider.findUnique({ where: { id: providerId } });
      if (adding && !validProvider(p, email)) return restart();
      if (adding && u.links.some(l => l.providerId === providerId)) return result('already_associated', 'This location is already associated.');
      let c;
      try { c = JSON.parse(u.verifyCode); } catch (_) { return restart(); }
      const expires = u.verifyCodeExpiresAt;
      if (!validProvider(p, email) || !c || c.v !== 1 || c.accountId !== u.id || c.providerId !== providerId
        || c.purpose !== (adding ? 'add_location' : 'first_enrollment') || typeof c.nonce !== 'string' || !/^[a-f0-9]{48}$/.test(c.nonce)
        || c.nonce !== challengeId || !equal(c.emailDigest, mac(['email', email]))
        || !Number.isInteger(c.failedAttempts) || c.failedAttempts < 0 || c.failedAttempts >= 5
        || !expires || expires <= date || typeof c.codeDigest !== 'string' || !/^[a-f0-9]{64}$/.test(c.codeDigest)) return restart();
      const where = { id: u.id, ...(adding ? { emailVerifiedAt: u.emailVerifiedAt } : { emailVerifiedAt: null, activeProviderId: null }), verifyCode: u.verifyCode,
        verifyCodeExpiresAt: { gt: date } };
      if (!equal(c.codeDigest, digest(c, expires, code))) {
        c.failedAttempts++;
        const exhausted = c.failedAttempts >= 5;
        const changed = await tx.providerUser.updateMany({ where, data: {
          verifyCode: exhausted ? null : JSON.stringify(c), verifyCodeExpiresAt: exhausted ? null : expires } });
        if (changed.count !== 1 || exhausted) return restart();
        return result('invalid_code', 'Incorrect code. Please try again.');
      }
      const changed = await tx.providerUser.updateMany({ where, data: { verifyCode: null, verifyCodeExpiresAt: null,
        ...(!adding ? { passwordHash, emailVerifiedAt: date, activeProviderId: providerId } : {}) } });
      if (changed.count !== 1) return restart();
      await tx.providerUserProvider.create({ data: { id: crypto.randomUUID(), providerUserId: u.id, providerId } });
      return adding ? result('associated', 'Location added.') : result('enrolled', 'Signup complete.', { accountId: u.id });
    });
  }
  const authenticatedCall = (fn, accountId, input) => typeof accountId === 'string' && accountId
    ? fn(input, accountId) : Promise.resolve(result('unauthorized', 'Authentication required.'));
  async function targets(accountId) {
    if (typeof accountId !== 'string' || !accountId) return result('unauthorized', 'Authentication required.');
    return transaction(async tx => {
      const u = await tx.providerUser.findUnique({ where: { id: accountId } });
      if (!u?.emailVerifiedAt) return result('unauthorized', 'A verified account is required.');
      const email = normalize(u.email);
      if (!email) return result('unauthorized', 'A verified account is required.');
      const providers = await tx.$queryRaw`SELECT p.id, p.name, p.city, p.state
        FROM "Provider" p WHERE p."internalRole" IS NULL
        AND ${email} = lower(btrim(p."providerLoginEmail", ${trimCharacters}))
        AND NOT EXISTS (SELECT 1 FROM "ProviderUserProvider" l
          WHERE l."providerId" = p.id AND l."providerUserId" = ${u.id})
        ORDER BY p.name, p.city, p.state, p.id`;
      return result('ok', '', { providers });
    });
  }
  return { start: input => startFlow(input), complete: input => completeFlow(input), targets,
    startAddLocation: (id, input) => authenticatedCall(startFlow, id, input),
    completeAddLocation: (id, input) => authenticatedCall(completeFlow, id, input) };
}
module.exports = { createProviderEnrollment };
