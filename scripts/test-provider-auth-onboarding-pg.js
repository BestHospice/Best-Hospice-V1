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
let date = new Date();
const api = createProviderEnrollment({ prisma:wrapped, secret:'synthetic-test-secret',hashPassword:p=>bcrypt.hash(p,10),now:()=>date });
const start=()=>api.start({providerId:'auth-test-provider',providerEmail:'owner@example.test'});
const complete=(r,over={})=>api.complete({email:'owner@example.test',providerId:'auth-test-provider',challengeId:r.challengeId,code:r.delivery.code,password:'synthetic-password',...over});
async function snapshot() { return { users:await prisma.providerUser.findMany(), links:await prisma.providerUserProvider.findMany() }; }
async function reset() {
  barrier=null;failAssociation=false;
  await prisma.providerUserProvider.deleteMany();await prisma.providerUser.deleteMany();await prisma.rateLimitEvent.deleteMany();
  date=new Date();return start();
}
(async()=>{
  const version=(await prisma.$queryRawUnsafe('SHOW server_version'))[0].server_version;
  assert(/^18\./.test(version));console.log('PostgreSQL '+version+'; Prisma '+require('@prisma/client/package.json').version);
  // This test owns the entire explicitly disposable database.
  await prisma.providerUserProvider.deleteMany();await prisma.providerUser.deleteMany();await prisma.provider.deleteMany();
  await prisma.provider.create({data:{id:'auth-test-provider',name:'Synthetic Auth Provider',email:'owner@example.test',providerLoginEmail:'owner@example.test',address:'1 Test St',city:'Test',state:'AZ',zip:'85001',lat:33,lon:-112,serviceRadiusKm:10}});
  assert.equal(await bcrypt.compare('anything',''),false,'provisional empty hash cannot authenticate');
  let r=await reset();arm();
  let out=await Promise.all([complete(r),complete(r)]);
  assert.equal(out.filter(x=>x.status==='enrolled').length,1);
  let s=await snapshot();assert.equal(s.links.length,1);assert(s.users[0].emailVerifiedAt);assert.equal(s.users[0].activeProviderId,'auth-test-provider');assert.equal(s.users[0].verifyCode,null);assert(await bcrypt.compare('synthetic-password',s.users[0].passwordHash));
  console.log('PASS concurrent valid completion: one success, one association, verified/active state committed, challenge cleared');
  const before=JSON.stringify(s);assert.equal((await complete(r)).status,'restart_required');assert.equal(JSON.stringify(await snapshot()),before);
  console.log('PASS replay: no account or association changes');
  r=await reset();const wrong=r.delivery.code==='100000'?'100001':'100000';
  for(let i=0;i<4;i++)assert.equal((await complete(r,{code:wrong})).status,'invalid_code');
  assert.equal(JSON.parse((await snapshot()).users[0].verifyCode).failedAttempts,4);
  arm();out=await Promise.all([complete(r,{code:wrong}),complete(r,{code:wrong})]);
  s=await snapshot();assert.equal(s.users[0].verifyCode,null);assert.equal(s.users[0].emailVerifiedAt,null);assert.equal(s.users[0].activeProviderId,null);assert.equal(s.links.length,0);
  assert(out.every(x=>x.status==='restart_required'));
  console.log('PASS concurrent fifth attempts: exhausted challenge, no access');
  r=await reset();date=new Date(+date+61000);arm();
  out=await Promise.all([start(),complete(r)]);s=await snapshot();
  if(out[0].status==='challenge_sent') {
    assert.equal(out[1].status,'restart_required');assert.equal(s.links.length,0);
    assert.equal(JSON.parse(s.users[0].verifyCode).nonce,out[0].challengeId);
    assert.equal((await complete(r)).status,'restart_required');
  } else { assert.equal(out[0].status,'existing_account');assert.equal(out[1].status,'enrolled');assert.equal(s.links.length,1); }
  console.log('PASS resend/completion race: valid serial ordering, no replaced challenge succeeds');
  r=await reset();date=new Date(+date+61000);await start();assert.equal((await complete(r)).status,'restart_required');assert.equal((await snapshot()).links.length,0);
  console.log('PASS committed resend invalidates previous challenge');
  r=await reset();const initial=JSON.stringify(await snapshot());failAssociation=true;
  await assert.rejects(complete(r),/forced-after-association/);assert.equal(JSON.stringify(await snapshot()),initial);
  console.log('PASS failure after association insert: password, verification, active selection and association rolled back');
  await reset();
  const existing=(await snapshot()).users[0];
  await prisma.providerUser.update({where:{id:existing.id},data:{email:'\towner@example.test\u00a0'}});
  const userCount=await prisma.providerUser.count();
  assert.equal((await start()).status,'manual_review');assert.equal(await prisma.providerUser.count(),userCount);
  console.log('PASS stored tab/NBSP email variant fails closed without duplicate account');
  assert(collisions>0,'Barrier must exercise actual serialization conflicts');
  console.log('PASS actual serialization conflicts retried: '+collisions);
})().catch(e=>{console.error(e);process.exitCode=1;}).finally(()=>prisma.$disconnect());
