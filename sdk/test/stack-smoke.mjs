// Explicit live test against the isolated mockauth OPS/Reth acceptance stack.
// This is not an Azure-provider login test and is excluded from unit npm test.
import assert from 'node:assert/strict';
import {readFile,writeFile} from 'node:fs/promises';
import {OpsClient,OpsError,RpcError} from '../dist/index.js';
const [baseUrl,acceptancePath,outputPath]=process.argv.slice(2);
if(!baseUrl||!acceptancePath||!outputPath)throw Error('Usage: node test/stack-smoke.mjs OPS_ORIGIN ACCEPTANCE_JSON OUTPUT_JSON');
const evidence=JSON.parse(await readFile(acceptancePath,'utf8'));
const checks=[];
async function login(role) {
  const client=new OpsClient({baseUrl});
  const challenge=await client.request('POST /api/v1/auth/request',{body:{}});
  const tokens=await client.request('POST /api/v1/auth/verify',{body:{session_id:challenge.session_id,jwz_token:`mock.did:test:ops-reth-${role}`}});
  assert.ok(tokens.access_token&&tokens.refresh_token);
  client.setSession({accessToken:tokens.access_token,refreshToken:tokens.refresh_token});
  await client.refresh();
  return client;
}
const author=await login('author');
checks.push('named human authentication through generated routes and real refresh rotation');
const readiness=await author.readiness();
assert.equal(readiness.execution?.mode,'reth');
assert.equal(readiness.execution?.ready,true);
const context=await author.context(evidence.orgId,'execution-rules');
assert.equal(context.active?.id,evidence.activeRevisionId);
assert.equal(context.viewer?.canActivate,true);
checks.push('live readiness and scoped active execution context');
const user=await login('user');
const addresses=await user.request('GET /api/v1/eth/addresses',{});
assert.ok(addresses.addresses?.[0]?.address);
const params=[{from:addresses.addresses[0].address,to:evidence.contract,data:'0x3fa4f245'},'latest'];
const preview=await author.preview(evidence.orgId,{candidateRevisionId:evidence.activeRevisionId,method:'eth_call',params,dryRun:true,principalId:evidence.principals.user});
assert.ok(preview&&typeof preview==='object'&&'policy' in preview&&'result' in preview);
checks.push('explicit audited human diagnostic reaches live Reth candidate evaluator');
await assert.rejects(user.rpc(evidence.orgId,'eth_call',params),error=>error instanceof RpcError||error instanceof OpsError);
checks.push('revoked active rule returns execution denial through SDK RPC');
const status=await user.waitForFinality(evidence.call,{timeoutMs:5000});
assert.equal(status.reconciled,true);assert.equal(status.execution.finalized,true);
assert.equal(status.transaction_hash,evidence.call);
const other=await login('other');
await assert.rejects(other.transactionStatus(evidence.call),error=>error instanceof OpsError&&error.status===404);
checks.push('finalized own transaction status and shared-signer principal isolation');
await writeFile(outputPath,JSON.stringify({stack:evidence.stack,orgId:evidence.orgId,checks},null,2)+'\n');
console.log(JSON.stringify({checks:checks.length,result:'passed'}));
