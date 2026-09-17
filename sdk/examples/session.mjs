import {OpsClient} from '../dist/index.js';

export async function clientFromEnvironment() {
	if(process.env.OPS_ACCESS_TOKEN&&process.env.OPS_AZURE_ACCESS_TOKEN)throw Error('Choose exactly one named credential source: OPS_ACCESS_TOKEN or OPS_AZURE_ACCESS_TOKEN');
  const client=new OpsClient({baseUrl:process.env.OPS_URL??'http://localhost:8080',
    session:process.env.OPS_ACCESS_TOKEN?{accessToken:process.env.OPS_ACCESS_TOKEN,refreshToken:process.env.OPS_REFRESH_TOKEN}:undefined});
  if(process.env.OPS_AZURE_ACCESS_TOKEN) await client.loginServicePrincipal(process.env.OPS_AZURE_ACCESS_TOKEN);
  if(!client.session)throw Error('Set OPS_AZURE_ACCESS_TOKEN or OPS_ACCESS_TOKEN to a named principal credential');
  // Explicit rotation; mutations are never transparently retried on 401.
  if(process.env.OPS_REFRESH==='1')await client.refresh();
  return client;
}
export function org() {
  if(!process.env.OPS_ORG_ID)throw Error('Set OPS_ORG_ID');
  return process.env.OPS_ORG_ID;
}
