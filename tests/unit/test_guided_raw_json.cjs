"use strict";
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const { test } = require("node:test");
const source = fs.readFileSync(path.join(__dirname, "../../llm-security-control-plane/guided-control-center/app.js"), "utf8");
const context = {};
const learning = {};
vm.runInNewContext(source.slice(source.indexOf('function verificationSummary('), source.indexOf('function renderLearningSupport(')), learning);
function completionHarness() {
  const celebrated = [];
  const ctx = {practiceGroups: [['P01'], ['P02', 'P03']], completedPractices: new Map(), celebratedPractices: new Set(),
    verificationSummary: learning.verificationSummary, renderPracticeProgress: () => {},
    celebratePractice: id => celebrated.push(id)};
  vm.runInNewContext(source.slice(source.indexOf('function recordPracticeCompletion('), source.indexOf('function selectTab(')), ctx);
  return {ctx, celebrated};
}

test('completion celebration needs the requested problem and a verified completed result', () => {
  const {ctx, celebrated} = completionHarness();
  const sample = {activity_id: 'P01', execution_id: 'a', verified_by: 'verifier', task_completed: true, course_verdict: 'PASS'};
  for (const change of [{resource_ready: true}, {verified_by: ''}, {execution_id: ''}, {task_completed: false},
                        {course_verdict: 'ERR'}, {client_error: true}, {activity_id: 'P02'}]) {
    ctx.recordPracticeCompletion({...sample, ...change}, 'P01');
    assert.equal(ctx.completedPractices.size, 0);
  }
  ctx.recordPracticeCompletion(sample, 'P99');
  assert.equal(celebrated.length, 0);
  ctx.recordPracticeCompletion(sample, 'P01');
  assert.deepEqual(celebrated, ['P01']);
  assert.equal(ctx.completedPractices.get('P01'), 'a');
});

test('repeat verification does not replay celebration and an incomplete result removes its own mark', () => {
  const {ctx, celebrated} = completionHarness();
  const sample = {activity_id: 'P01', execution_id: 'a', verified_by: 'verifier', task_completed: true, course_verdict: 'PASS'};
  ctx.recordPracticeCompletion(sample, 'P01');
  ctx.recordPracticeCompletion({...sample, execution_id: 'b'}, 'P01');
  ctx.recordPracticeCompletion({...sample, activity_id: 'P02', course_verdict: 'HIT'}, 'P02');
  assert.deepEqual(celebrated, ['P01', 'P02']);
  ctx.recordPracticeCompletion({...sample, task_completed: false, course_verdict: 'ERR'}, 'P01');
  assert.equal(ctx.completedPractices.has('P01'), false);
  assert.equal(ctx.completedPractices.has('P02'), true);
});

test('comparison requires a graded execution and never includes response text', () => {
  const sample = {activity_id: 'P01', execution_id: 'a', verified_by: 'verifier', task_completed: true, course_verdict: 'PASS', prompt: 'private'};
  assert.equal(learning.verificationSummary({...sample, execution_id: undefined}), null);
  assert.equal(learning.verificationSummary({...sample, resource_ready: true}), null);
  assert.equal(learning.verificationSummary({...sample, course_verdict: 'ERR'}).completed, '미완료');
  assert.equal(learning.verificationSummary(sample).prompt, undefined);
  assert.equal(learning.verificationSummary(sample).digest, '미확인');
});
test('failure guidance does not infer causes from arbitrary text', () => {
  assert.equal(learning.failureCategory({http_status: 422}), '입력');
  assert.equal(learning.failureCategory({http_status: 501}), '구현');
  assert.equal(learning.failureCategory({failure_category: 'evidence'}), '증거');
  assert.match(learning.failureCategory({error: 'AWS access denied'}), /미분류/);
});
vm.runInNewContext(source.slice(source.indexOf("function formatRawJson("), source.indexOf("async function request(")), context);

test("transport failure is ERR without invented downstream evidence", () => {
  let result;
  const ctx = { renderEnvelope: value => { result = value; } };
  vm.runInNewContext(source.slice(source.indexOf("function renderError("), source.indexOf("async function execute(")), ctx);
  ctx.renderError(new Error("Failed to fetch"));
  assert.equal(result.course_verdict, "ERR");
  assert.equal(result.client_error, true);
  assert.equal(result.stage_calls.length, 0);
  assert.equal(result.task_completed, undefined);
  assert.match(result.reason, /아직 알 수 없습니다/);
  assert.equal(result.error, "Failed to fetch");
});

test("verified failure retains its specific next check but cannot become PASS", () => {
  let result;
  const ctx = { renderEnvelope: value => { result = value; } };
  vm.runInNewContext(source.slice(source.indexOf("function renderError("), source.indexOf("async function execute(")), ctx);
  ctx.renderError({ message: "HTTP error", detail: {activity_id: "P01", task_completed: false,
    course_verdict: "PASS", reason: "AWS 접근 거부", next_check: "Gateway의 AWS 권한을 확인합니다."} });
  assert.equal(result.course_verdict, "ERR");
  assert.equal(result.task_completed, false);
  assert.equal(result.reason, "AWS 접근 거부");
  assert.equal(result.next_check, "Gateway의 AWS 권한을 확인합니다.");
});

test("large integers, decimals and exponent spelling are preserved", () => {
  const text = '{"ns":1790268749899188247,"negative":-9007199254740993,"n":1.2300e+25}';
  const rendered = context.formatRawJson(text);
  assert.ok(rendered.includes("1790268749899188247"));
  assert.ok(rendered.includes("-9007199254740993"));
  assert.ok(rendered.includes("1.2300e+25"));
});

test("escaped strings, nested containers and empty values remain valid JSON", () => {
  const text = JSON.stringify({ value: '한글 " { : , } \\ \n <script>', a: [[], {}, true, null, false, { n: 4 }] });
  assert.equal(context.formatRawJson(text), JSON.stringify(JSON.parse(text), null, 2));
});

test("request retains exact raw response beside parsed display fields", async () => {
  const text = '{"activity_id":"P17","result":{"started_ns":1790268749899188247}}';
  const state = { csrfToken: "test", rawResponses: new WeakMap(),
    fetch: async () => ({ ok: true, text: async () => text }) };
  vm.runInNewContext(source.slice(source.indexOf("function formatRawJson("), source.indexOf("function setBusy(")), state);
  const payload = await state.request("/api/test", {});
  assert.ok(state.rawResponses.get(payload).includes("1790268749899188247"));
  assert.equal(payload.activity_id, "P17");
});

test("P20 summary distinguishes missing evidence from actual zero or unfinished execution", () => {
  const ctx = {};
  vm.runInNewContext(source.slice(source.indexOf('function p20Summary('), source.indexOf('function renderEnvelope(')), ctx);
  assert.equal(ctx.p20Summary({}).requested[1], undefined);
  assert.equal(ctx.p20Summary({}).effective[1], undefined);
  const values = ctx.p20Summary({receipt: {execution_status: 'error', phase: 'risk', cases: [], closed: false}});
  assert.equal(values.provider[1], '오류');
  assert.equal(values.requested[1], 0);
  assert.equal(values.effective[1], '미종료');
  assert.equal(values.output[1], '미확인');
});

test("P04 shows synthetic mode and leaves unknown counts unreported", () => {
  const ctx = {};
  vm.runInNewContext(source.slice(source.indexOf('function p04Summary('), source.indexOf('function p12Summary(')), ctx);
  const missing = ctx.p04Summary({suite_contract_verified: false, cases: []});
  assert.equal(missing.requested[1], undefined);
  assert.equal(missing.effective[1], undefined);
  assert.equal(missing.output[1], '미확인');
  const result = ctx.p04Summary({provider_mode: 'contract', suite_contract_verified: true,
    source_digest: 'a'.repeat(64), cases: Array.from({length: 27}, (_, i) => ({
      product: i < 4 ? {product_result_verified: true} : null}))});
  assert.equal(result.provider[1], '합성 사례');
  assert.equal(result.requested[1], 27);
  assert.equal(result.effective[1], 4);
});

test("P04 preparation is not a grade and clears prior successful evidence", () => {
  const fields = {}, nodes = new Map();
  const byId = (id) => {
    if (!nodes.has(id)) nodes.set(id, {hidden: false, textContent: 'PASS', className: 'pass',
      querySelector: (selector) => byId(id + selector), replaceChildren: () => {fields.cleared = true;}});
    return nodes.get(id);
  };
  const ctx = {rawResponses: new WeakMap(), byId, setText: (key, value) => {fields[key] = value;}};
  vm.runInNewContext(source.slice(source.indexOf('function renderEnvelope('), source.indexOf('function renderError(')), ctx);
  ctx.renderEnvelope({activity_id: 'P04', resource_ready: true, operation_id: 'op', task_completed: false,
    preparation: {state: 'ready', resources: {guardrail: {guardrailIdentifier: 'p04-id', guardrailVersion: 'DRAFT'},
      policy_digest: 'b'.repeat(64)}}});
  assert.equal(nodes.get('verdictstrong').textContent, '미판정');
  assert.equal(nodes.get('task-completion').textContent, 'P04 과제: 미완료');
  assert.equal(fields['model-id'], 'p04-id');
  assert.equal(fields['requested-max'], 'DRAFT');
  assert.equal(fields['source-digest'], null);
  assert.equal(fields.cleared, true);
});

test("P12 shows verified counts only and does not manufacture zero calls", () => {
  const ctx = {};
  vm.runInNewContext(source.slice(source.indexOf('function p12Summary('), source.indexOf('function p20Summary(')), ctx);
  assert.equal(ctx.p12Summary({}).requested[1], undefined);
  assert.equal(ctx.p12Summary({}).effective[1], undefined);
  assert.equal(ctx.p12Summary({cases: [], task_completed: false}).requested[1], 0);
  assert.equal(ctx.p12Summary({cases: [], task_completed: false}).output[1], '미확인');
  const result = {suite_id: 'suite', source_digest: 'a'.repeat(64), cases: [{}, {}],
                  provider_call_count: 4, task_completed: true};
  assert.equal(ctx.p12Summary(result).model[1], 'a'.repeat(12));
  assert.equal(ctx.p12Summary(result).effective[1], 4);
  assert.equal(ctx.p12Summary(result).output[1], '없음');
  assert.equal(ctx.p12Summary({failed_case: 'normal'}).output[1], 'normal');
});

test("P03 summary separates contract evidence and does not invent zero searches", () => {
  const ctx = {};
  vm.runInNewContext(source.slice(source.indexOf('function p03Summary('), source.indexOf('function p12Summary(')), ctx);
  const missing = ctx.p03Summary({case_contract_verified: false, cases: []});
  assert.equal(missing.requested[1], undefined);
  assert.equal(missing.effective[1], undefined);
  assert.equal(missing.output[1], '미확인');
  const result = ctx.p03Summary({provider_mode: 'contract', case_contract_verified: true,
    source_digest: 'a'.repeat(64), cases: [{outcome: 'ready'}, {outcome: 'waiting'}, {outcome: 'rejected'}]});
  assert.equal(result.provider[1], '합성 사례');
  assert.equal(result.model[1], 'a'.repeat(12));
  assert.equal(result.requested[1], 3);
  assert.equal(result.effective[1], 1);
  assert.equal(result.output[1], '전체 대조됨');
});

test("P03 preparation never displays a security PASS or a completed task", () => {
  const fields = {};
  const nodes = new Map();
  const byId = (id) => {
    if (!nodes.has(id)) nodes.set(id, {hidden: false, textContent: '', className: '',
      querySelector: (selector) => byId(id + selector), replaceChildren: () => { fields.beltCleared = true; }});
    return nodes.get(id);
  };
  const ctx = {rawResponses: new WeakMap(), byId, setText: (key, value) => {fields[key] = value;}};
  vm.runInNewContext(source.slice(source.indexOf('function renderEnvelope('), source.indexOf('function renderError(')), ctx);
  ctx.renderEnvelope({activity_id: 'P03', resource_ready: true, operation_id: 'operation',
    task_completed: false, next_check: 'build', preparation: {resources: {binding: {
      provider_ingestion_job_id: 'job', knowledge_base_id: 'kb'}, source_uris: ['s3://fixture/document']},
      evidence: {document: {status: 'COMPLETE'}}}});
  assert.equal(nodes.get('verdictstrong').textContent, '미판정');
  assert.equal(nodes.get('task-completion').textContent, 'P03 과제: 미완료');
  assert.equal(fields['model-id'], 'job');
  assert.equal(fields['forwarded-max'], 'COMPLETE');
  assert.equal(fields['source-digest'], null);
  assert.equal(fields.beltCleared, true);
});

test("P02 summary requires verified cases and never turns missing evidence into zero", () => {
  const start = source.indexOf('  if (payload.activity_id === "P02"');
  const code = source.slice(start, source.indexOf('\n  }\n', start) + 5);
  function render(result) {
    const fields = {};
    vm.runInNewContext(code, {
      payload: {activity_id: 'P02', contract_version: 'p02-document-v1', execution_id: 'suite', result},
      setText: (key, value) => { fields[key] = value; }
    });
    return fields;
  }
  const empty = render({case_contract_verified: false, cases: [], embedding_dimension: null});
  assert.equal(empty['provider-id'], 'suite');
  assert.equal(empty['requested-max'], null);
  assert.equal(empty['forwarded-max'], null);
  assert.equal(empty['output-tokens'], undefined);
  const ready = render({case_contract_verified: true, cases: Array(22).fill({}), embedding_dimension: 1024,
    resource_evidence: {after: {binding: {embedding_model_id: 'titan', data_source_id: 'ds'}}}});
  assert.equal(ready['requested-max'], 22);
  assert.equal(ready['forwarded-max'], 1024);
  assert.equal(ready['model-id'], 'titan');
  assert.equal(ready['output-tokens'], 'ds');
});
