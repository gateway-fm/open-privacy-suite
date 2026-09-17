import test from 'node:test';
import assert from 'node:assert/strict';
import { OpsClient, OpsError, RpcError } from '../dist/index.js';

const response = (body, status = 200) => new Response(JSON.stringify(body), {status, headers:{'content-type':'application/json'}});
const session = {accessToken:'named-access', refreshToken:'named-refresh'};
function fixture(handler) {
  const calls = [];
  const client = new OpsClient({baseUrl:'http://localhost:8080', session, fetch:async (url, init) => {
    const call = {url:String(url), ...init, headers:Object.fromEntries(new Headers(init.headers))};
    calls.push(call); return handler(call, calls.length);
  }});
  return {client, calls};
}

test('draft preserves exact source and sends only named identity', async () => {
  const {client,calls} = fixture(() => response({id:'draft'},201));
  const source = '{"spec":{"policy":{}},"spec":{"policy":{"bindings":[]}}}';
  await client.submitDraft('org','execution-rules',source);
  assert.equal(calls[0].body,source);
  assert.equal(calls[0].headers.authorization,'Bearer named-access');
  assert.equal(calls[0].headers['x-admin-token'],undefined);
  assert.equal(calls[0].redirect,'error');
});

test('service exchange is unauthenticated and refresh rotation is serialized', async () => {
  let unblock;
  const gate = new Promise(resolve => {unblock=resolve;});
  const {client,calls} = fixture(async call => {
    if(call.url.endsWith('/refresh')) await gate;
    return response({access_token:'new-access',refresh_token:'new-refresh',token_type:'Bearer',expires_in:300});
  });
  await client.loginServicePrincipal('azure-provider-token');
  assert.equal(calls[0].headers.authorization,undefined);
  assert.deepEqual(JSON.parse(calls[0].body),{access_token:'azure-provider-token'});
  const first=client.refresh(),second=client.refresh();
  unblock(); await Promise.all([first,second]);
  assert.equal(calls.filter(c=>c.url.endsWith('/refresh')).length,1);
  assert.deepEqual(client.session,{accessToken:'new-access',refreshToken:'new-refresh'});
});

test('mutation authorization errors are never automatically retried', async () => {
  const {client,calls}=fixture(()=>response({error:'expired'},401));
  await assert.rejects(client.submitDraft('org','groups','{}'), e=>e instanceof OpsError && e.status===401);
  assert.equal(calls.length,1);
});

test('review captures its bundle before awaiting and activation uses that exact set', async () => {
  const {client,calls}=fixture(()=>response({revisions:[{id:'draft',kind:'execution-rules',digest:'d1'},{id:'sibling',kind:'groups',digest:'d2'}]}));
  const coactivate=['sibling'];
  const pending=client.reviewDraft('org','execution-rules','draft',coactivate);
  coactivate[0]='unreviewed';
  const reviewed=await pending;
  assert.ok(Object.isFrozen(reviewed.coactivate));
  await client.activateReviewed(reviewed);
  assert.deepEqual(JSON.parse(calls[1].body),{coactivate:['sibling']});
  await assert.rejects(client.activateWithCI(reviewed,{candidateDigests:{draft:'stale',sibling:'d2'}}),/reviewed/);
  assert.equal(calls.length,2);
});

test('independent CI evidence binds digests by configuration kind',async()=>{
  const {client,calls}=fixture(()=>response({revisions:[{id:'draft',kind:'execution-rules',digest:'d1'}]}));
  const reviewed=await client.reviewDraft('org','execution-rules','draft');
  const approval={candidateDigests:{'execution-rules':'d1'},scope:{kind:'organization',id:'org'},signature:'external-signature'};
  await client.activateWithCI(reviewed,approval);
  assert.deepEqual(JSON.parse(calls[1].body).approval,approval);
});

test('node preview uses own identity and leaves diagnostics explicit', async () => {
  const {client,calls}=fixture(()=>response({result:'0x',policy:{would_allow:true}}));
  await client.preview('org',{candidateRevisionId:'draft',method:'eth_call',params:[{from:'0x1234'}]});
  assert.equal(JSON.parse(calls[0].body).dryRun,undefined);
  assert.equal(JSON.parse(calls[0].body).principalId,undefined);
});

test('RPC detects protocol errors and status awaits actual finalized reconciliation', async () => {
  const {client,calls}=fixture((call,n)=> {
    if(call.url.includes('/rpc/')) return response({jsonrpc:'2.0',id:1,error:{code:-32000,message:'denied'}});
    return response({status:'included',reconciled:n>2,execution:{finalized:n>2}});
  });
  await assert.rejects(client.rpc('org','eth_call',[{}]),e=>e instanceof RpcError);
  const status=await client.waitForFinality('0xhash',{pollIntervalMs:1,timeoutMs:1000});
  assert.equal(status.reconciled,true);
  assert.equal(calls.length,3);
});

test('generated routes encode path parameters and reject credential-bearing base URLs',async()=>{
  const {client,calls}=fixture(()=>response({revisions:[]}));
  await client.request('GET /api/v1/admin/orgs/{org_id}/configuration/{kind}/revisions',{path:{org_id:'org/a',kind:'groups'}});
  assert.match(calls[0].url,/org%2Fa/);
  assert.throws(()=>new OpsClient({baseUrl:'https://user:secret@example.org'}),/base URL/);
});

function deferredLoginFixture() {
  const pending=[];
  const {client}=fixture(()=>new Promise(resolve=>pending.push(resolve)));
  const complete=(index,name)=>pending[index](response({access_token:name,refresh_token:`${name}-refresh`}));
  return {client,complete};
}
test('pending login cannot overwrite an explicitly replaced session',async()=>{
  const {client,complete}=deferredLoginFixture();
  const login=client.loginServicePrincipal('provider-A');
  client.setSession({accessToken:'principal-B'});
  complete(0,'principal-A');
  await assert.rejects(login,/Session changed/);
  assert.equal(client.session.accessToken,'principal-B');
});
test('newer login intention wins even when older login finishes last',async()=>{
  const {client,complete}=deferredLoginFixture();
  const first=client.loginServicePrincipal('provider-A');
  const second=client.loginServicePrincipal('provider-B');
  complete(1,'principal-B');await second;
  complete(0,'principal-A');
  await assert.rejects(first,/Session changed/);
  assert.equal(client.session.accessToken,'principal-B');
});
test('pending refresh cannot overwrite a newer login intention',async()=>{
  const {client,complete}=deferredLoginFixture();
  const refresh=client.refresh();
  const login=client.loginServicePrincipal('provider-B');
  complete(0,'principal-A');
  await assert.rejects(refresh,/Session changed/);
  complete(1,'principal-B');await login;
  assert.equal(client.session.accessToken,'principal-B');
});
