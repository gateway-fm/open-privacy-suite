import {readFile} from 'node:fs/promises';
import {clientFromEnvironment,org} from './session.mjs';

const client=await clientFromEnvironment();
const [command,file]=process.argv.slice(2);
let result;
switch(command) {
  case 'readiness': result=await client.readiness();break;
  case 'onboard':
    result=await client.request('POST /api/v1/admin/orgs/{org_id}/memberships/by-did',{
      path:{org_id:org()},body:JSON.parse(await readFile(file,'utf8'))});break;
  case 'rpc': {
    const request=JSON.parse(await readFile(file,'utf8'));
    result=await client.rpc(org(),request.method,request.params,{visibleTo:request.visibleTo});break;
  }
  case 'submit': {
    // Signing is performed by the caller's wallet or secret manager. Never put
    // private keys in policy source, prompts, manifests or SDK output.
    const raw=(await readFile(file,'utf8')).trim();
    const hash=await client.rpc(org(),'eth_sendRawTransaction',[raw]);
    process.stdout.write(`${JSON.stringify({transactionHash:hash,status:'accepted'})}\n`);
    result=await client.waitForFinality(hash);break;
  }
  case 'status':result=await client.transactionStatus(file);break;
  default:throw Error('Usage: node examples/operate.mjs readiness | onboard FILE | rpc FILE | submit RAW_TX_FILE | status HASH');
}
process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
