'use strict';
const fs=require('fs'),assert=require('node:assert/strict');
const source=fs.readFileSync('server.js','utf8'),page=fs.readFileSync('provider-dashboard-home.html','utf8');
const region=source.slice(source.indexOf('// Add Location never uses'),source.indexOf('// Provider auth: login'));
const routes={};const auth=()=>{},limit=()=>{};let call,delivered=false;
const service={targets:async id=>{call=id;return {status:'ok',providers:[]};},startAddLocation:async(id,body)=>{call={id,body};return {status:'challenge_sent',challengeId:'nonce',delivery:{email:'synthetic@example.test',code:'123456'}};},completeAddLocation:async(id,body)=>{call={id,body};return {status:'associated'};}};
new Function('app','requireProviderAuth','authRateLimit','providerEnrollment','EMAIL_ENABLED','sendGenericEmail','enrollmentHttpStatus',region)(
  {get:(p,...h)=>routes[p]=h,post:(p,...h)=>routes[p]=h},auth,limit,service,true,async()=>{delivered=true;},()=>400);
const response=()=>({status(n){this.code=n;return this;},json(v){this.body=v;return this;}});
(async()=>{
  for(const [path,handlers] of Object.entries(routes)){assert.equal(handlers[0],auth);if(!path.endsWith('targets'))assert.equal(handlers[1],limit);}
  // Execute the real authentication middleware to verify missing JWT stops routing.
  const authRegion=source.slice(source.indexOf('function requireProviderAuth('),source.indexOf('async function getProviderContext('));
  const authenticate=new Function('jwt','PROVIDER_JWT_SECRET',authRegion+'; return requireProviderAuth;')({},'test-secret');
  let advanced=false;const denied=response();authenticate({headers:{}},denied,()=>advanced=true);assert.equal(denied.code,401);assert(!advanced);
  const out=response();await routes['/api/provider-auth/add-location/start'].at(-1)({providerUserId:'trusted-account',body:{accountId:'forged',providerId:'target'}},out);
  assert.equal(call.id,'trusted-account');assert(delivered);assert(!JSON.stringify(out.body).includes('123456'));assert(!out.body.delivery);
  await routes['/api/provider-auth/add-location/complete'].at(-1)({providerUserId:'trusted-account',body:{providerId:'target'}},response());assert.equal(call.id,'trusted-account');
  assert(!region.includes('prisma.providerUser.update'));assert(!region.includes('jwt.sign'));
  console.log('PASS authentication middleware, trusted JWT account, IP protection and sanitized route output');

  const ui=page.slice(page.indexOf('    // Add Location is revealed'),page.indexOf("    const tokenKey = 'provider_jwt';"));
  async function harness(failSend=false) {
    const els={};const el=id=>els[id] ||= {hidden:true,disabled:false,value:'target',textContent:'',options:[],appendChild(o){this.options.push(o);},focus(){}};
    const requests=[];let reloads=0;
    const replies=[{status:'ok',providers:[{id:'target',name:'Same Name',city:'City',state:'AZ'}]}, {status:'challenge_sent',challengeId:'nonce'},{status:'associated'},{ok:true}];
    const fakeFetch=async(path,options)=>{requests.push({path,body:options.body?JSON.parse(options.body):null});const data=failSend&&requests.length===2?{status:'restart_required',error:'Email failed'}:replies.shift();return {ok:!(failSend&&requests.length===2),json:async()=>data};};
    new Function('document','localStorage','fetch','window',ui)({getElementById:el,createElement:()=>({})},{getItem:()=> 'synthetic-token'},fakeFetch,{location:{reload(){reloads++;}}});
    await new Promise(r=>setImmediate(r));
    return {els,requests,get reloads(){return reloads;}};
  }
  const h=await harness();assert.equal(h.els['add-location'].hidden,false);assert(h.els['add-location-target'].options[0].textContent.includes('City, AZ'));
  await h.els['add-location-start'].onclick();assert.equal(h.requests.length,2);assert.equal(h.els['add-location-verification'].hidden,false);assert(!h.requests.some(r=>r.path==='/api/provider/select'));
  h.els['add-location-code'].value='123456';await h.els['add-location-complete'].onclick();
  assert.deepEqual(h.requests[2].body,{providerId:'target',challengeId:'nonce',code:'123456'});assert.equal(h.requests[3].path,'/api/provider/select');assert.deepEqual(h.requests[3].body,{providerId:'target'});assert.equal(h.reloads,1);
  const failed=await harness(true);await failed.els['add-location-start'].onclick();assert.equal(failed.els['add-location-status'].textContent,'Email failed');assert.equal(failed.els['add-location-verification'].hidden,true);assert.equal(failed.reloads,0);
  console.log('PASS UI target labels, provider-bound code, switch only after success, email failure');
  for(const script of page.matchAll(/<script>([\s\S]*?)<\/script>/g))new Function(script[1]);
  console.log('PASS dashboard inline script syntax');
})().catch(e=>{console.error(e);process.exitCode=1;});
