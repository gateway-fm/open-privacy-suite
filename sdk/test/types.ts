import {OpsClient} from '../src/index.js';
const client=new OpsClient({baseUrl:'http://localhost:8080'});
void client.request('GET /api/v1/admin/orgs/{org_id}/configuration/{kind}/context',{path:{org_id:'org',kind:'groups'}});
// @ts-expect-error unknown routes must not silently become untyped requests
void client.request('GET /unknown',{});
// @ts-expect-error route parameters are mandatory
void client.request('GET /api/v1/admin/orgs/{org_id}/configuration/{kind}/context',{});
// @ts-expect-error configuration kind is a generated closed enum
void client.context('org','not-a-stream');
const status=client.transactionStatus('0xhash');
void status.then(value=>value.execution?.finalized);
