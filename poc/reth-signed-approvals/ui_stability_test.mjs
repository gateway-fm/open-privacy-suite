import { chromium } from '../../.tmp/gasstorm-browser/node_modules/playwright/index.mjs';
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
const base=process.env.GASSTORM_UI_URL || 'http://127.0.0.1:18000';
const out=process.env.OPS_UI_TEST_EVIDENCE;
const fixedRate=Number(process.env.OPS_UI_FIXED_RATE || 2000);
const runMs=Number(process.env.OPS_UI_RUN_MS || 75000);
assert(out);await fs.mkdir(out,{recursive:true});
const browser=await chromium.launch({channel:'chrome',headless:true});
const page=await browser.newPage({viewport:{width:1440,height:1900}});
const frames=[];page.on('websocket',ws=>{if(ws.url().endsWith('/ws/loadgen'))ws.on('framereceived',f=>{try{frames.push(JSON.parse(f.payload.toString()))}catch{}})});
const status=async()=>{const r=await fetch(base+'/api/loadgen/status');assert(r.ok);return r.json()};
const wait=ms=>new Promise(r=>setTimeout(r,ms));
async function until(fn,ms=15000){const end=Date.now()+ms;while(Date.now()<end){if(await fn())return;await wait(200)}throw Error('condition timed out')}
const samples=[];const result={};
try{
 await page.goto(base+'/load-test/',{waitUntil:'networkidle'});
 if ((await status()).status !== 'idle') {
  const initial=(await status()).status;
  if(initial==='running') await page.getByRole('button',{name:'Stop',exact:true}).click();
  if(initial==='verifying') await page.getByRole('button',{name:'Stop verification',exact:true}).click();
  await until(async()=>(await status()).status==='completed',30000);
  if(await page.getByRole('button',{name:'Reset',exact:true}).count()) {
   await page.getByRole('button',{name:'Reset',exact:true}).click();
   await until(async()=>(await status()).status==='idle');
  }
 }
 await page.getByRole('button',{name:'Through Privacy Proxy',exact:true}).click();
 await page.getByRole('tab',{name:'Constant',exact:true}).click();
 const inputs=page.getByRole('spinbutton');console.log('inputs',await inputs.count());
 assert.equal(await inputs.count(),2);
 await inputs.nth(0).fill(String(fixedRate));await inputs.nth(1).fill('120');await inputs.nth(1).blur();
 await page.getByRole('button',{name:'Start Test',exact:true}).click();
 await until(async()=>(await status()).status==='running');
 const started=Date.now();
 while(Date.now()-started<runMs){
  const s=await status(); const pool=await (await fetch(base+'/poc/status')).json();
  samples.push({at:Date.now(),...s,pool:pool.pool});
  if(samples.length%10===0){console.log(JSON.stringify({elapsed:s.elapsedMs,sent:s.txSent,confirmed:s.txConfirmed,failed:s.txFailed,tps:s.currentTps,pool:pool.pool})); await fs.writeFile(out+'/samples.json',JSON.stringify(samples))}
  assert.equal(s.status,'running');
  await wait(500);
 }
 await page.screenshot({path:out+`/constant-${fixedRate}.png`,fullPage:true});
 await fs.writeFile(out+`/constant-${fixedRate}.txt`,await page.locator('body').innerText());
 result.beforeStop=await status();
 // Deliberate fixed-rate overload may fail requests; Stop/Reset must still work.
 result.offeredRate=fixedRate;
 let at=Date.now();await page.getByRole('button',{name:'Stop',exact:true}).click();
 await until(async()=>(await status()).status==='completed',15000);result.stopMs=Date.now()-at;
 await page.getByRole('button',{name:'Reset',exact:true}).waitFor({timeout:10000});
 await page.screenshot({path:out+'/stopped.png',fullPage:true});
 at=Date.now();await page.getByRole('button',{name:'Reset',exact:true}).click();
 await until(async()=>(await status()).status==='idle');result.resetMs=Date.now()-at;
 await page.getByRole('button',{name:'Start Test',exact:true}).waitFor();
 await inputs.nth(0).fill('1000');await inputs.nth(1).fill('10');await inputs.nth(1).blur();
 await page.getByRole('button',{name:'Start Test',exact:true}).click();
 await until(async()=>(await status()).status==='running');
 await until(async()=>(await status()).status==='completed',90000);
 result.retest=await status();
 assert(result.retest.txConfirmed>9000,'retest was blocked by the previous run');
 assert.equal(result.retest.txFailed,0);
 await page.screenshot({path:out+'/retest.png',fullPage:true});
 await page.getByRole('button',{name:'Reset',exact:true}).click();
 await until(async()=>(await status()).status==='idle');
 assert(result.beforeStop.txConfirmed>0,'the load test never confirmed a transaction');
 console.log('PASS',JSON.stringify(result));
}finally{
 await fs.writeFile(out+'/samples.json',JSON.stringify(samples));
 await fs.writeFile(out+'/frames.json',JSON.stringify(frames));
 await fs.writeFile(out+'/result.json',JSON.stringify(result,null,2));
 await page.screenshot({path:out+'/final.png',fullPage:true}).catch(()=>{});
 await browser.close();
}
