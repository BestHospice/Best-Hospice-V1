'use strict';
const assert = require('node:assert/strict');
const fs = require('fs');
const cp = require('child_process');
const { createProviderEnrollment } = require('../provider-enrollment');
let passed = 0;
async function test(name, fn) { await fn(); passed++; console.log('PASS ' + name); }
function harness() {
  const h = { date: new Date('2026-09-13T00:00:00Z'), failLink: false,
    state: { providers: [{ id: 'p', providerLoginEmail: 'owner@example.test', internalRole: null, billingMode: 'free' }], users: [], links: [], rates: [] } };
  let queue = Promise.resolve();
  const prisma = { $transaction(fn, options) {
    assert.equal(options.isolationLevel, 'Serializable');
    const work = queue.then(async () => {
      const s = structuredClone(h.state);
      const user = id => { const u = s.users.find(u => u.id === id); return u ? { ...u, links: s.links.filter(l => l.providerUserId === id) } : null; };
      const tx = {
        $queryRaw: async (_, email) => s.users.filter(u => u.email.trim().toLowerCase() === email).map(u => ({ id: u.id })),
        provider: { findUnique: async ({where}) => s.providers.find(p => p.id === where.id) || null },
        providerUser: {
          findUnique: async ({where}) => user(where.id),
          create: async ({data}) => { const u = { emailVerifiedAt: null, activeProviderId: null, verifyCode: null, verifyCodeExpiresAt: null, ...data }; s.users.push(u); return u; },
          update: async ({where,data}) => Object.assign(s.users.find(u => u.id === where.id), data),
          updateMany: async ({where,data}) => {
            const u = s.users.find(u => u.id === where.id && u.verifyCode === where.verifyCode
              && !u.emailVerifiedAt && !u.activeProviderId && u.verifyCodeExpiresAt > where.verifyCodeExpiresAt.gt);
            if (!u) return {count:0}; Object.assign(u,data); return {count:1};
          }
        },
        providerUserProvider: { create: async ({data}) => { if(h.failLink) throw Error('injected failure'); s.links.push(data); } },
        rateLimitEvent: { findMany: async ({where}) => s.rates.filter(r => r.ipHash === where.ipHash && r.createdAt >= where.createdAt.gte).sort((a,b) => b.createdAt-a.createdAt),
          create: async ({data}) => s.rates.push(data) }
      };
      const out = await fn(tx); h.state = s; return out;
    });
    queue = work.catch(() => {}); return work;
  } };
  h.api = createProviderEnrollment({ prisma, secret: 'test-only-secret', hashPassword: async p => 'hashed:'+p, now: () => h.date });
  h.start = () => h.api.start({providerId:'p',providerEmail:' Owner@Example.Test '});
  h.complete = (r, over={}) => h.api.complete({email:'owner@example.test',providerId:'p',challengeId:r.challengeId,code:r.delivery.code,password:'password8',...over});
  return h;
}
(async () => {
  await test('start is inert; bound digest and crypto-generated six digits', async () => {
    const h=harness(),r=await h.start(),u=h.state.users[0],c=JSON.parse(u.verifyCode);
    assert.equal(h.state.links.length,0);assert.equal(u.activeProviderId,null);assert.equal(u.emailVerifiedAt,null);
    assert.match(r.delivery.code,/^\d{6}$/);assert(!u.verifyCode.includes(r.delivery.code));
    assert.equal(c.accountId,u.id);assert.equal(c.providerId,'p');assert.equal(c.purpose,'first_enrollment');assert.equal(c.v,1);
    assert.equal(u.verifyCodeExpiresAt-h.date,1200000);
    assert(fs.readFileSync('provider-enrollment.js','utf8').includes('crypto.randomInt(100000, 1000000)'));
  });
  await test('verified account start does not mutate account; complete cannot replace password', async () => {
    const h=harness(),r=await h.start();h.state.users[0].emailVerifiedAt=h.date;h.state.users[0].passwordHash='original';
    const before=JSON.stringify(h.state.users);assert.equal((await h.start()).status,'existing_account');
    assert.equal((await h.complete(r)).status,'restart_required');assert.equal(JSON.stringify(h.state.users),before);
  });
  for(const anomaly of ['link','active']) await test('unverified anomaly '+anomaly,async()=>{
    const h=harness();await h.start();if(anomaly==='link')h.state.links.push({providerUserId:h.state.users[0].id,providerId:'p'});else h.state.users[0].activeProviderId='p';
    assert.equal((await h.start()).status,'manual_review');
  });
  for(const field of ['accountId','providerId','purpose','v','emailDigest']) await test('reject altered binding '+field,async()=>{
    const h=harness(),r=await h.start(),c=JSON.parse(h.state.users[0].verifyCode);c[field]='wrong';h.state.users[0].verifyCode=JSON.stringify(c);
    assert.equal((await h.complete(r)).status,'restart_required');assert.equal(h.state.links.length,0);
  });
  await test('wrong target and changed email rejected',async()=>{
    const h=harness(),r=await h.start();assert.equal((await h.complete(r,{providerId:'other'})).status,'restart_required');
    h.state.providers[0].providerLoginEmail='changed@example.test';assert.equal((await h.complete(r)).status,'restart_required');
  });
  await test('internal target rejected at both steps',async()=>{
    const h=harness(),r=await h.start();h.state.providers[0].internalRole='cms_reference';
    assert.equal((await h.start()).status,'invalid_request');assert.equal((await h.complete(r)).status,'restart_required');
  });
  for(const bad of ['123456','{bad',JSON.stringify({v:2})]) await test('legacy/malformed challenge rejected '+bad,async()=>{
    const h=harness(),r=await h.start();h.state.users[0].verifyCode=bad;assert.equal((await h.complete(r)).status,'restart_required');
  });
  await test('expired and replaced challenges rejected; cooldown enforced',async()=>{
    const h=harness(),r=await h.start();assert.equal((await h.start()).status,'rate_limited');
    h.date=new Date(+h.date+61000);const next=await h.start();assert.equal((await h.complete(r)).status,'restart_required');
    h.date=new Date(+h.date+1200001);assert.equal((await h.complete(next)).status,'restart_required');
  });
  await test('five wrong codes consume challenge even with concurrent attempts',async()=>{
    const h=harness(),r=await h.start(),code=r.delivery.code==='100000'?'100001':'100000';
    assert.equal((await h.complete(r,{code})).status,'invalid_code');assert.equal(JSON.parse(h.state.users[0].verifyCode).failedAttempts,1);
    await Promise.all(Array.from({length:4},()=>h.complete(r,{code})));assert.equal(h.state.users[0].verifyCode,null);
    assert.equal((await h.complete(r)).status,'restart_required');
  });
  await test('concurrent successful completion and replay grant access once',async()=>{
    const h=harness(),r=await h.start();const out=await Promise.all([h.complete(r),h.complete(r)]);
    assert.equal(out.filter(x=>x.status==='enrolled').length,1);assert.equal(h.state.links.length,1);
    const u=h.state.users[0];assert.equal(u.activeProviderId,'p');assert(u.emailVerifiedAt);assert.equal(u.passwordHash,'hashed:password8');assert.equal(u.verifyCode,null);
    assert.equal((await h.complete(r)).status,'restart_required');
  });
  await test('association failure rolls back password, verification and active selection',async()=>{
    const h=harness(),r=await h.start();const before=JSON.stringify(h.state);h.failLink=true;
    await assert.rejects(h.complete(r));assert.equal(JSON.stringify(h.state),before);
  });
  await test('free and billed identical; repeated resend limited',async()=>{
    for(const mode of ['free','billed']){const h=harness();h.state.providers[0].billingMode=mode;const r=await h.start();assert.equal((await h.complete(r)).status,'enrolled');}
    const h=harness();for(let i=0;i<5;i++){assert.equal((await h.start()).status,'challenge_sent');h.date=new Date(+h.date+61000);}assert.equal((await h.start()).status,'rate_limited');
  });
  await test('login, location selection and legacy link remain unchanged',async()=>{
    const base=cp.execFileSync('git',['show','origin/main:server.js'],{encoding:'utf8'}),current=fs.readFileSync('server.js','utf8');
    for(const [a,b] of [['// Provider auth: login','// PUBLIC list of providers.'],['// Select active provider for logged-in user','// Provider leads count since date'],['// Provider auth: link account','// Provider dashboard metrics']])
      assert.equal(current.slice(current.indexOf(a),current.indexOf(b,current.indexOf(a))),base.slice(base.indexOf(a),base.indexOf(b,base.indexOf(a))));
  });
  await test('email is sent after commit; HTTP never exposes delivery code; email failure is safe',async()=>{
    const src=fs.readFileSync('server.js','utf8');
    const region=src.slice(src.indexOf('// First-time enrollment deliberately'),src.indexOf('// Add Location never uses getProviderContext'));
    const routes={};let committed=false, failEmail=false, delivered=false;
    const enrollment={start:async()=>{committed=true;return {status:'challenge_sent',message:'sent',challengeId:'nonce',delivery:{email:'owner@example.test',code:'123456'}};},complete:async()=>({status:'enrolled',accountId:'u'})};
    new Function('require','prisma','PROVIDER_JWT_SECRET','bcrypt','app','authRateLimit','EMAIL_ENABLED','sendGenericEmail','jwt',region)(
      ()=>({createProviderEnrollment:()=>enrollment}),{},'test',{},
      {post:(path,...handlers)=>{routes[path]=handlers.at(-1);}},()=>{},true,
      async()=>{assert(committed);if(failEmail)throw Error('transport failed');delivered=true;},
      {sign:()=>{assert(committed);return 'test-jwt';}});
    const response=()=>({statusCode:200,status(n){this.statusCode=n;return this;},json(data){this.body=data;return this;}});
    const res=response();await routes['/api/provider-auth/signup-start']({body:{}},res);
    assert(delivered);assert(!JSON.stringify(res.body).includes('123456'));assert(!res.body.delivery);
    failEmail=true;const failed=response();await routes['/api/provider-auth/signup-start']({body:{}},failed);assert.equal(failed.statusCode,503);
  });
  await test('account collisions, missing configured email, rolling completion limit',async()=>{
    const h=harness();h.state.providers[0].providerLoginEmail='';h.state.providers[0].email='owner@example.test';assert.equal((await h.start()).status,'invalid_request');
    h.state.providers[0].providerLoginEmail='owner@example.test';const r=await h.start();
    h.state.users.push({...h.state.users[0],id:'duplicate',email:'OWNER@example.test'});assert.equal((await h.start()).status,'manual_review');
    h.state.users.pop();
    for(let i=0;i<20;i++)await h.complete(r,{challengeId:'old'});
    assert.equal((await h.complete(r)).status,'rate_limited');
  });
  await test('UI retains enrollment target and supports existing-account, restart, resend',async()=>{
    const html=fs.readFileSync('provider-dashboard.html','utf8');
    new Function(html.match(/<script>([\s\S]*?)<\/script>/)[1]);
    for(const text of ["data.status === 'existing_account'",'enrollment = { providerId, challengeId: data.challengeId }',"err.status === 'restart_required'","id=\"resend-code\"",'...(enrollment || {})'])assert(html.includes(text),text);
  });
  console.log(passed+' tests passed');
})().catch(e=>{console.error(e);process.exitCode=1;});
