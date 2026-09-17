import {readFile} from 'node:fs/promises';
import {clientFromEnvironment,org} from './session.mjs';

// Explicit, separate invocation using an independent approver's named session,
// or a service session and a manifest from its trusted external approval system.
const id=process.argv[2];
if(!id)throw Error('Usage: node examples/activate.mjs REVISION_ID [SIGNED_CI_APPROVAL.json]');
const client=await clientFromEnvironment();
const kind=process.env.OPS_CONFIGURATION_KIND??'execution-rules';
const reviewed=await client.reviewDraft(org(),kind,id,(process.env.OPS_COACTIVATE??'').split(',').filter(Boolean));
const result=process.argv[3]
  ?await client.activateWithCI(reviewed,JSON.parse(await readFile(process.argv[3],'utf8')))
  :await client.activateReviewed(reviewed);
process.stdout.write(`${JSON.stringify(result,null,2)}\n`);
