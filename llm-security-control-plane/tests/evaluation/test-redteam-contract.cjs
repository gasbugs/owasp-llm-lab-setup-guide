const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const Target = require('./redteam-target.cjs');
const Nova = require('./redteam-nova.cjs');
const FullScan = require('./fullscan-target.cjs');

(async () => {
  const originalDirectory = process.cwd();
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'redteam-contract-'));
  process.chdir(directory);
  process.env.CONTROL_PLANE_ACCESS_TOKEN = 'target-secret-test';
  process.env.BEDROCK_GATEWAY_TOKEN = 'gateway-secret-test';
  const target = new Target();
  let sent;
  global.fetch = async (url, request) => {
    sent = {url, request};
    return {ok: true, json: async () => ({reply: 'blocked', application_decision: 'block', upstream_called: false})};
  };
  assert.equal((await target.callApi('first attempt')).output, 'blocked');
  assert.equal(sent.request.headers.Authorization, 'Bearer target-secret-test');
  assert.deepEqual(JSON.parse(sent.request.body), {message: 'first attempt', classification: 'none', purpose: 'public_information'});
  global.fetch = async () => ({ok: true, json: async () => ({reply: 'partial', application_decision: 'allow', upstream_called: true, guardrail: {stages: [{stage: 'bedrock_main', stop_reason: 'length'}]}})});
  assert.match((await target.callApi('second attempt')).error, /incomplete/);
  const records = fs.readFileSync('results/application-responses.jsonl', 'utf8');
  assert.equal(records.trim().split('\n').length, 2);
  assert.ok(!records.includes('target-secret-test'));
  assert.ok(!records.includes('gateway-secret-test'));
  global.fetch = async () => ({ok: false, status: 401});
  assert.equal((await target.callApi('expired')).error, 'Application HTTP 401');
  assert.equal(fs.readFileSync('results/application-responses.jsonl', 'utf8'), records);
  global.fetch = async (url, request) => {
    sent = {url, request};
    return {ok: true, json: async () => ({choices: [{finish_reason: 'stop', message: {content: 'candidate'}}], usage: {total_tokens: 3}})};
  };
  assert.equal((await new Nova().callApi('generate a candidate')).output, 'candidate');
  assert.equal(sent.url, 'http://llm-security-bedrock-gateway:8080/v1/chat/completions');
  assert.equal(sent.request.headers.Authorization, 'Bearer gateway-secret-test');
  assert.equal(JSON.parse(sent.request.body).model, 'us.amazon.nova-lite-v1:0');
  const fullscan = new FullScan();
  let logins = 0;
  const tokens = [];
  global.fetch = async (url, request) => {
    if (url.endsWith('/.well-known/login')) {
      assert.deepEqual(JSON.parse(request.body), {username: 'public-reader', password: 'public-reader-demo'});
      logins += 1;
      return {ok: true, json: async () => ({access_token: `scan-secret-${logins}`, expires_in: 300})};
    }
    tokens.push(request.headers.Authorization);
    return {ok: true, json: async () => ({reply: 'blocked', application_decision: 'block', upstream_called: false})};
  };
  for (let index = 0; index < 5; index += 1) assert.equal((await fullscan.callApi(`scan ${index}`)).output, 'blocked');
  assert.equal(logins, 3);
  assert.deepEqual(tokens, ['Bearer scan-secret-1', 'Bearer scan-secret-1', 'Bearer scan-secret-2', 'Bearer scan-secret-2', 'Bearer scan-secret-3']);
  fullscan.expiresAt = Date.now() + 59000;
  assert.equal((await fullscan.callApi('new group before expiry')).output, 'blocked');
  assert.equal(logins, 4);
  assert.ok(!fs.readFileSync('results/application-responses.jsonl', 'utf8').includes('scan-secret'));
  let calls = 0;
  global.fetch = async () => { calls += 1; return {ok: false, status: 401}; };
  assert.equal((await new FullScan().callApi('login rejected')).error, 'Login HTTP 401');
  assert.equal(calls, 1);
  global.fetch = async () => { calls += 1; return {ok: true, json: async () => ({access_token: 'invalid-lifetime', expires_in: 30})}; };
  calls = 0;
  assert.match((await new FullScan().callApi('invalid token lifetime')).error, /no usable Token lifetime/);
  assert.equal(calls, 1);
  process.chdir(originalDirectory);
  fs.rmSync(directory, {recursive: true});
  console.log('redteam-provider-contract=PASS');
})().catch(error => { console.error(error); process.exitCode = 1; });
