// Run against a live `gasstorm.sh ui` session. Real browser controls, no store injection.
import assert from 'node:assert/strict';
import fs from 'node:fs/promises';
import path from 'node:path';
import { gzipSync } from 'node:zlib';

// Playwright lives wherever the session installed it; import it by path at run time.
const playwrightRoot = process.env.OPS_PLAYWRIGHT_ROOT;
assert(playwrightRoot, 'Set OPS_PLAYWRIGHT_ROOT to a directory containing node_modules/playwright');
const { chromium } = await import(`${playwrightRoot}/node_modules/playwright/index.mjs`);

const base = process.env.GASSTORM_UI_URL || 'http://127.0.0.1:18000';
const evidence = process.env.OPS_UI_TEST_EVIDENCE;
assert(evidence, 'Set OPS_UI_TEST_EVIDENCE');
await fs.mkdir(evidence, {recursive: true});
const browser = await chromium.launch({channel: 'chrome', headless: true});
const page = await browser.newPage({viewport: {width: 1440, height: 1100}});
const frames = [];
page.on('websocket', ws => {
  if (ws.url().endsWith('/ws/loadgen')) ws.on('framereceived', frame => {
    try { frames.push(JSON.parse(frame.payload.toString())); } catch {}
  });
});
const api = async path => {
  const r = await fetch(base + '/api/loadgen' + path);
  assert(r.ok, `${path}: ${r.status}`); return await r.json();
};
const results = [];
const session = JSON.parse(await fs.readFile(path.join(evidence, '../ui-session.json'), 'utf8'));
const rpc = async (method, params) => {
  const response = await fetch(session.node, {method: 'POST', headers: {'Content-Type': 'application/json'},
    body: JSON.stringify({jsonrpc: '2.0', id: 1, method, params})});
  const value = await response.json(); assert(!value.error, JSON.stringify(value)); return value.result;
};
try {
  await page.goto(base + '/load-test/', {waitUntil: 'networkidle'});
  await page.getByRole('button', {name: 'Through Privacy Proxy', exact: true}).click();
  await page.getByRole('tab', {name: 'Adaptive', exact: true}).click();
  const inputs = page.getByRole('spinbutton');
  assert.equal(await inputs.count(), 4);
  const settings = [process.env.OPS_UI_INITIAL || '100', process.env.OPS_UI_STEP || '25',
    process.env.OPS_UI_TARGET_PENDING || '1000', process.env.OPS_UI_DURATION || '10'];
  for (const [index, value] of settings.entries()) {
    await inputs.nth(index).fill(value); await inputs.nth(index).blur();
  }
  const workloads = (process.env.OPS_UI_TEST_WORKLOADS || 'eth-transfer,erc20-approve').split(',');
  for (const workload of workloads) {
    const labels = {'eth-transfer': /ETH Transfer/, 'erc20-approve': /ERC20 Approve/, 'storage-write': /Storage Write/};
    assert(labels[workload], 'Unsupported browser workload: ' + workload);
    await page.getByRole('combobox').click();
    await page.getByRole('option', {name: labels[workload]}).click();
    const start = page.waitForResponse(r => r.url().endsWith('/api/loadgen/start') && r.request().method() === 'POST');
    await page.getByRole('button', {name: 'Start Test', exact: true}).click();
    const response = await start;
    assert.equal(response.status(), 200, await response.text());
    const samples = [];
    const deadline = Date.now() + Number(settings[3]) * 1000 + 240000;
    let peak = 0;
    while (Date.now() < deadline) {
      const s = await api('/status');
      const pool = await (await fetch(base + '/poc/status')).json();
      samples.push({at: Date.now(), rethPool: {pending: Number(pool.pool.pending), queued: Number(pool.pool.queued)}, ...s});
      if (samples.length % 10 === 0) await fs.writeFile(`${evidence}/${workload}-samples.json`, JSON.stringify(samples));
      assert.notEqual(s.status, 'error', s.error);
      if (s.status === 'running' && s.currentTps > peak) {
        peak = s.currentTps;
        if (process.env.OPS_UI_CAPTURE_PEAK === '1') {
          await page.screenshot({path: `${evidence}/${workload}-peak.png`, fullPage: true});
          await fs.writeFile(`${evidence}/${workload}-peak.json`, JSON.stringify({
            capturedAt: new Date().toISOString(), triggeringSample: s,
            visibleText: await page.locator('body').innerText()
          }, null, 2));
        }
      }
      if (s.status === 'completed') break;
      await new Promise(resolve => setTimeout(resolve, 500));
    }
    assert.equal(samples.at(-1).status, 'completed');
    assert(samples.at(-1).txConfirmed > 0);
    if (process.env.OPS_UI_CAPACITY !== '1') assert.equal(samples.at(-1).txFailed, 0);
    assert(samples.some(s => s.currentTps > 0), 'Live TPS chart has no measured throughput');
    assert(new Set(samples.filter(s => s.status === 'running').map(s => s.targetTps)).size > 1, 'Adaptive rate did not change');
    const history = (await api('/history?limit=1')).runs[0];
    assert.equal(history.config.numAccounts, 10);
    assert.equal(history.config.privacyMode, true);
    assert.equal(history.config.pattern, 'adaptive');
    assert.equal(history.config.transactionType, workload);
    let logs = [];
    const persistedBy = Date.now() + 30000;
    while (true) {
      const p = await api(`/history/${history.id}/transactions?limit=1000&offset=${logs.length}`);
      if (!logs.length && !p.transactions?.length) {
        assert(Date.now() < persistedBy, 'Transaction logs were not persisted');
        await new Promise(resolve => setTimeout(resolve, 100)); continue;
      }
      logs.push(...p.transactions);
      if (logs.length >= p.total) break;
    }
    const unique = [...new Map(logs.map(tx => [tx.txHash, tx])).values()];
    console.log('Checking unique receipts after measurement:', unique.length);
    const receipts = [];
    for (let i = 0; i < unique.length; i += 256) {
      // Read-only batches against the node, after the measured test has ended.
      const batch = unique.slice(i, i + 256);
      const response = await fetch(session.node, {method: 'POST', headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(batch.map((tx, id) => ({jsonrpc: '2.0', id,
          method: 'eth_getTransactionReceipt', params: [tx.txHash]})))});
      const answers = await response.json();
      assert(Array.isArray(answers), JSON.stringify(answers));
      const byId = new Map(answers.map(answer => [answer.id, answer]));
      assert.equal(byId.size, batch.length);
      receipts.push(...batch.map((tx, id) => {
        const answer = byId.get(id);
        assert(answer && !answer.error, JSON.stringify(answer));
        if (answer.result) assert.equal(answer.result.transactionHash.toLowerCase(), tx.txHash.toLowerCase());
        return {hash: tx.txHash, receipt: answer.result};
      }));
    }
    const successful = receipts.filter(r => r.receipt?.status === '0x1').length;
    assert(successful > 0);
    assert.equal(logs.length, unique.length, 'Transaction log contains duplicate hashes');
    assert(successful >= history.txConfirmed, 'Displayed confirmations exceed unique successful receipts');
    assert(!receipts.some(r => r.receipt && r.receipt.status !== '0x1'));
    const block = await rpc('eth_getBlockByNumber', ['latest', false]);
    assert.equal(Number(block.gasLimit), session.gas_limit);
    assert(Math.abs(Number(block.timestamp) - Date.now()/1000) < 10, 'Block timestamps must track the live chart clock');
    await fs.writeFile(`${evidence}/${workload}-receipts.json.gz`, gzipSync(JSON.stringify(receipts), {level: 1}));
    await fs.writeFile(`${evidence}/${workload}.json`, JSON.stringify({history, samples}, null, 2));
    // The dashboard scrolls inside a fixed-height shell; fullPage alone clips
    // the bottom of the chart. Resize only after measurement has finished.
    await page.setViewportSize({width: 1440, height: 1900});
    await page.waitForTimeout(300);
    await page.screenshot({path: `${evidence}/${workload}.png`, fullPage: true});
    const visibleText = await page.locator('body').innerText();
    await fs.writeFile(`${evidence}/${workload}-visible.txt`, visibleText);
    const displayedPeak = visibleText.match(/([\d,]+)\s+tx\/s peak/);
    assert(displayedPeak, 'Dashboard did not display the peak');
    results.push({workload, confirmed: history.txConfirmed, successfulReceipts: successful,
      missingReceipts: receipts.filter(r => !r.receipt).length, failed: history.txFailed,
      duplicateLogEntries: logs.length - unique.length, confirmedCounterDelta: history.txConfirmed - successful,
      peakLiveTps: Math.max(...samples.map(s => s.currentTps || 0)),
      dashboardPeakTps: Number(displayedPeak[1].replaceAll(',', '')), adaptive: true, wallets: 10});
    console.log('PASS browser', JSON.stringify(results.at(-1)));
    await page.getByRole('button', {name: 'Reset', exact: true}).click();
  }
  assert(frames.length > 10, 'Live loadgen WebSocket did not deliver metrics');
  await fs.writeFile(`${evidence}/websocket-frames.json`, JSON.stringify(frames));
  await fs.writeFile(`${evidence}/browser-results.json`, JSON.stringify({results, websocketFrames: frames.length}, null, 2));
} catch (error) {
  await page.screenshot({path: `${evidence}/failure.png`, fullPage: true});
  throw error;
} finally {
  await browser.close();
}
