'use strict';
// Only an explicitly named disposable local PG18 database is accepted.
const assert = require('node:assert/strict');
const { PrismaClient } = require('@prisma/client');
const bcrypt = require('bcryptjs');
const { createProviderEnrollment } = require('../provider-enrollment');
const raw = process.env.TEST_DATABASE_URL;
let url;
try { url = new URL(raw); } catch (_) { throw Error('Set TEST_DATABASE_URL to a disposable local auth database'); }
assert(['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname));
assert(/^\/bh_auth_phase1_test(?:_[a-z0-9]+)?$/.test(url.pathname));
assert(!url.search && !url.hash, 'No connection overrides permitted');
const prisma = new PrismaClient({ datasources: { db: { url: raw } } });
let barrier = null, failAssociation = false, collisions = 0;
const wrapped = {
  $transaction: (fn, options) => prisma.$transaction(async tx => {
    assert.equal((await tx.$queryRawUnsafe('SHOW transaction_isolation'))[0].transaction_isolation, 'serializable');
    const proxy = new Proxy(tx, { get(target, prop) {
      if (prop === 'providerUser') return new Proxy(target[prop], { get(model, method) {
        if (method !== 'findUnique') return model[method].bind(model);
        return async args => {
          const row = await model.findUnique(args);
          const b = barrier;
          if (b && b.arrivals < 2) {
            b.arrivals++; if (b.arrivals === 2) b.release();
            await b.ready;
          }
          return row;
        };
      } });
      if (prop === 'providerUserProvider') return new Proxy(target[prop], { get(model, method) {
        if (method !== 'create') return model[method].bind(model);
        return async args => { const row = await model.create(args); if (failAssociation) throw Error('forced-after-association'); return row; };
      } });
      const value=target[prop];return typeof value === 'function' ? value.bind(target) : value;
    } });
    return fn(proxy);
  }, { ...options, timeout: 15000 }).catch(e => { if(e.code==='P2034')collisions++;throw e; })
};
function arm() { let release; const ready = new Promise(r=>{release=r;});barrier={arrivals:0,release,ready}; }
let date = new Date(), count = 0;
const api = createProviderEnrollment({ prisma:wrapped, secret:'synthetic-test-secret',hashPassword:()=>{throw Error('Add Location must not hash passwords');},now:()=>date });
const accountId='location-account';
const start=(providerId='target')=>api.startAddLocation(accountId,{providerId});
const complete=(r,over={})=>api.completeAddLocation(accountId,{providerId:'target',challengeId:r.challengeId,code:r.delivery.code,...over});
const snap=async()=>({users:await prisma.providerUser.findMany({orderBy:{id:'asc'}}),links:await prisma.providerUserProvider.findMany({orderBy:{id:'asc'}})});
let original;
async function reset() {
  barrier=null;failAssociation=false;date=new Date();
  await prisma.providerUserProvider.deleteMany();await prisma.providerUser.deleteMany();await prisma.rateLimitEvent.deleteMany();await prisma.provider.deleteMany();
  for(const id of ['original','target','other','internal','mismatch']) await prisma.provider.create({data:{id,name:'Same Synthetic Name',email:'contact@example.test',providerLoginEmail:id==='mismatch'?'different@example.test':'owner@example.test',internalRole:id==='internal'?'cms_reference':null,address:'1 Test St',city:id,state:'AZ',zip:'85001',lat:33,lon:-112,serviceRadiusKm:10,billingMode:'free'}});
  await prisma.providerUser.create({data:{id:accountId,email:'owner@example.test',passwordHash:await bcrypt.hash('synthetic-password',10),emailVerifiedAt:date,activeProviderId:'original'}});
  await prisma.providerUserProvider.create({data:{id:'original-link',providerUserId:accountId,providerId:'original'}});
  original=await snap();
}
function preserved(s) {assert.equal(s.users[0].passwordHash,original.users[0].passwordHash);assert.equal(+s.users[0].emailVerifiedAt,+original.users[0].emailVerifiedAt);assert.equal(s.users[0].activeProviderId,'original');assert(s.links.some(l=>l.id==='original-link'));}
async function test(name,fn){await reset();await fn();count++;console.log('PASS '+name);}
(async()=>{
  const version=(await prisma.$queryRawUnsafe('SHOW server_version'))[0].server_version;assert(/^18\./.test(version));console.log('PostgreSQL '+version+'; Prisma '+require('@prisma/client/package.json').version);
  await test('authentication and current verification required',async()=>{
    assert.equal((await api.startAddLocation(null,{providerId:'target'})).status,'unauthorized');
    await prisma.providerUser.update({where:{id:accountId},data:{emailVerifiedAt:null}});assert.equal((await start()).status,'unauthorized');
  });
  await test('selector returns only eligible noninternal unassociated location labels',async()=>{
    const out=await api.targets(accountId);assert.deepEqual(out.providers.map(p=>p.id).sort(),['other','target']);
    for(const p of out.providers)assert.deepEqual(Object.keys(p).sort(),['city','id','name','state']);
    assert.equal((await start('internal')).status,'invalid_request');assert.equal((await start('mismatch')).status,'invalid_request');
  });
  await test('start grants nothing and preserves all credential/active state',async()=>{
    const r=await start(),s=await snap(),c=JSON.parse(s.users[0].verifyCode);assert.equal(s.links.length,1);preserved(s);
    assert.equal(c.purpose,'add_location');assert.equal(c.accountId,accountId);assert.equal(c.providerId,'target');assert(!s.users[0].verifyCode.includes(r.delivery.code));
    assert.equal((await complete(r,{providerId:'other'})).status,'restart_required');
    assert.equal((await api.completeAddLocation('unknown',{providerId:'target',code:r.delivery.code,challengeId:r.challengeId})).status,'unauthorized');
  });
  await test('already associated start is nonmutating',async()=>{
    assert.equal((await start('original')).status,'already_associated');assert.deepEqual(await snap(),original);
  });
  for(const field of ['accountId','providerId','purpose','emailDigest','v'])await test('reject challenge binding '+field,async()=>{
    const r=await start(),u=(await snap()).users[0],c=JSON.parse(u.verifyCode);c[field]=field==='purpose'?'first_enrollment':'wrong';
    await prisma.providerUser.update({where:{id:accountId},data:{verifyCode:JSON.stringify(c)}});assert.equal((await complete(r)).status,'restart_required');assert.equal((await snap()).links.length,1);
  });
  for(const value of ['123456','{bad','null'])await test('reject legacy/malformed '+value,async()=>{
    const r=await start();await prisma.providerUser.update({where:{id:accountId},data:{verifyCode:value}});assert.equal((await complete(r)).status,'restart_required');
  });
  await test('wrong codes increment; concurrent fifth failures exhaust',async()=>{
    const r=await start(),code=r.delivery.code==='100000'?'100001':'100000';
    for(let i=1;i<=4;i++){assert.equal((await complete(r,{code})).status,'invalid_code');assert.equal(JSON.parse((await snap()).users[0].verifyCode).failedAttempts,i);}
    arm();await Promise.all([complete(r,{code}),complete(r,{code})]);const s=await snap();assert.equal(s.users[0].verifyCode,null);assert.equal(s.links.length,1);preserved(s);
  });
  await test('resend replaces challenge, cooldown, expiry',async()=>{
    const r=await start();assert.equal((await start()).status,'rate_limited');date=new Date(+date+61000);const replacement=await start();assert.equal((await complete(r)).status,'restart_required');date=new Date(+date+1200001);assert.equal((await complete(replacement)).status,'restart_required');
  });
  for(const change of ['email','internal','unverified','account-email'])await test('completion revalidates '+change,async()=>{
    const r=await start();
    if(change==='email')await prisma.provider.update({where:{id:'target'},data:{providerLoginEmail:'changed@example.test'}});
    if(change==='internal')await prisma.provider.update({where:{id:'target'},data:{internalRole:'cms_reference'}});
    if(change==='unverified')await prisma.providerUser.update({where:{id:accountId},data:{emailVerifiedAt:null}});
    if(change==='account-email')await prisma.providerUser.update({where:{id:accountId},data:{email:'changed@example.test'}});
    assert(['restart_required','unauthorized'].includes((await complete(r)).status));assert.equal((await snap()).links.length,1);
  });
  await test('concurrent success and replay create exactly one free-provider link; switch only afterward',async()=>{
    const r=await start();arm();const out=await Promise.all([complete(r),complete(r)]);assert.equal(out.filter(x=>x.status==='associated').length,1);assert.equal(out.filter(x=>x.status==='already_associated').length,1);
    const s=await snap();preserved(s);assert.equal(s.links.length,2);assert.equal(s.users[0].verifyCode,null);
    assert.equal((await complete(r)).status,'already_associated');assert.deepEqual(await snap(),s);
    const fs=require('fs');const source=fs.readFileSync('server.js','utf8');const region=source.slice(source.indexOf('// Select active provider for logged-in user'),source.indexOf('// Provider leads count since date'));
    let handler;new Function('app','requireProviderAuth','prisma',region)({post:(_p,_auth,h)=>{handler=h;}},()=>{},prisma);
    const res={code:200,status(n){this.code=n;return this;},json(v){this.body=v;}};
    await handler({body:{providerId:'target'},providerUserId:accountId},res);assert(res.body.ok);assert.equal((await snap()).users[0].activeProviderId,'target');
  });
  await test('rollback after insert leaves original link, credentials and challenge intact',async()=>{
    const r=await start(),before=await snap();failAssociation=true;await assert.rejects(complete(r),/forced-after-association/);assert.deepEqual(await snap(),before);
  });
  await test('resend/completion race serializes safely',async()=>{
    const r=await start();date=new Date(+date+61000);arm();const out=await Promise.all([start(),complete(r)]);const s=await snap();preserved(s);
    if(out[1].status==='associated'){assert.equal(s.links.length,2);assert.equal(out[0].status,'already_associated');}
    else {assert.equal(out[0].status,'challenge_sent');assert.equal(s.links.length,1);assert.equal((await complete(r)).status,'restart_required');}
  });
  await test('rolling limits survive resend',async()=>{
    for(let i=0;i<5;i++){assert.equal((await start()).status,'challenge_sent');date=new Date(+date+61000);}assert.equal((await start()).status,'rate_limited');
  });
  assert(collisions>0);console.log(count+' tests passed; actual serialization conflicts retried: '+collisions);
})().catch(e=>{console.error(e);process.exitCode=1;}).finally(()=>prisma.$disconnect());
