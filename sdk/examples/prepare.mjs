import {readFile} from 'node:fs/promises';
import {clientFromEnvironment,org} from './session.mjs';

const client=await clientFromEnvironment();
const kind=process.env.OPS_CONFIGURATION_KIND??'execution-rules';
const organization=org();
const context=await client.context(organization,kind);
if(!process.argv[2]) {
  // Export the complete editable source. Edit a copy and pass its path to
  // this command. Server context contains migration diagnostics separately.
  process.stdout.write(`${JSON.stringify(context,null,2)}\n`);
} else {
  const source=await readFile(process.argv[2],'utf8');
  const draft=await client.submitDraft(organization,kind,source);
  if(!draft.id)throw Error('Server returned a draft without a revision ID');
  const siblings=(process.env.OPS_COACTIVATE??'').split(',').filter(Boolean);
  const reviewed=await client.reviewDraft(organization,kind,draft.id,siblings);
  let preview;
  if(process.env.OPS_PREVIEW_FILE) {
    const request=JSON.parse(await readFile(process.env.OPS_PREVIEW_FILE,'utf8'));
    if(request.dryRun||request.principalId)throw Error('Author example previews only its own ordinary execution');
    preview=await client.preview(organization,{...request,candidateRevisionId:draft.id});
  }
  process.stdout.write(`${JSON.stringify({draft,review:reviewed.review,candidateDigests:reviewed.candidateDigests,preview},null,2)}\n`);
  process.stderr.write('Draft prepared. Independent human review or trusted CI approval is required for activation.\n');
}
