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
  const ctx = {practiceGroups: [['P01'], ['P02', 'P03']], completedPractices: new Map(), recheckPractices: new Map(), celebratedPractices: new Set(),
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

test('each successful verification replays celebration and an incomplete result removes its own mark', () => {
  const {ctx, celebrated} = completionHarness();
  const sample = {activity_id: 'P01', execution_id: 'a', verified_by: 'verifier', task_completed: true, course_verdict: 'PASS'};
  ctx.recordPracticeCompletion(sample, 'P01');
  ctx.recordPracticeCompletion({...sample, execution_id: 'b'}, 'P01');
  ctx.recordPracticeCompletion({...sample, activity_id: 'P02', course_verdict: 'HIT'}, 'P02');
  assert.deepEqual(celebrated, ['P01', 'P01', 'P02']);
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
test('unavailable progress demotes old marks and a late refresh cannot overwrite a new attempt', async () => {
  const state = {progressRequest: 0, executionPending: false, completedPractices: new Map([['P01', 'saved']]),
    recheckPractices: new Map(), renderPracticeProgress: () => {}, setText: () => {},
    fetch: async () => ({ok: false})};
  vm.runInNewContext(source.slice(source.indexOf('async function restorePracticeProgress('), source.indexOf('function dismissCelebration(')), state);
  await state.restorePracticeProgress();
  assert.equal(state.completedPractices.size, 0);
  assert.equal(state.recheckPractices.has('P01'), true);
  state.completedPractices.set('P02', 'new');
  state.fetch = async () => {state.progressRequest++; return {ok: false};};
  await state.restorePracticeProgress();
  assert.equal(state.completedPractices.has('P02'), true);
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
  const state = { csrfToken: "test", refreshBrowserSession: async () => {}, rawResponses: new WeakMap(), p01ResultHomes: [],
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
  const ctx = {showMissionResults: () => {}, renderReportedCases: () => {}, rawResponses: new WeakMap(), p01ResultHomes: [], renderResourceProgress: () => {}, updateKnowledgeLinks: () => {}, updateGuardrailChat: () => {}, document: {querySelector: selector => byId(selector)}, byId, setText: (key, value) => {fields[key] = value;}};
  vm.runInNewContext(source.slice(source.indexOf('function renderEnvelope('), source.indexOf('function renderError(')), ctx);
  ctx.renderEnvelope({activity_id: 'P04', resource_ready: true, operation_id: 'op', task_completed: false,
    preparation: {state: 'ready', resources: {guardrail: {guardrailIdentifier: 'p04-id', guardrailVersion: 'DRAFT'},
      policy_digest: 'b'.repeat(64)}}});
  assert.equal(nodes.get('.inspection').hidden, true);
  assert.equal(nodes.get('.receipt').hidden, true);
  assert.equal(fields['execution-state'], '자원 준비 완료 · 미채점');

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
  const ctx = {showMissionResults: () => {}, renderReportedCases: () => {}, rawResponses: new WeakMap(), p01ResultHomes: [], renderResourceProgress: () => {}, updateKnowledgeLinks: () => {}, updateGuardrailChat: () => {}, document: {querySelector: selector => byId(selector)}, byId, setText: (key, value) => {fields[key] = value;}};
  vm.runInNewContext(source.slice(source.indexOf('function renderEnvelope('), source.indexOf('function renderError(')), ctx);
  ctx.renderEnvelope({activity_id: 'P03', resource_ready: true, operation_id: 'operation',
    task_completed: false, next_check: 'build', preparation: {resources: {binding: {
      provider_ingestion_job_id: 'job', knowledge_base_id: 'kb'}, source_uris: ['s3://fixture/document']},
      evidence: {document: {status: 'COMPLETE'}}}});
  assert.equal(nodes.get('.inspection').hidden, true);
  assert.equal(nodes.get('.receipt').hidden, true);
  assert.equal(fields['execution-state'], '자원 준비 완료 · 미채점');

});

test("P02 summary requires verified cases and never turns missing evidence into zero", () => {
  const start = source.indexOf('  if (payload.activity_id === "P02" && payload.contract_version');
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

function caseHarness() {
  const elements = {};
  const element = () => ({children: [], textContent: '', hidden: false,
    append(...items) { this.children.push(...items); }, replaceChildren() { this.children = []; }});
  const ctx = {caseCatalog: {}, activeProblem: "P05", gradingCredentialKey: key => /^(token|authorization|password)$/.test(key), formatRawJson: context.formatRawJson, document: {createElement: element}, byId: id => elements[id] ||= element()};
  Object.assign(ctx, {caseCatalog: {}, activeProblem: "P05", gradingCredentialKey: key => /^(token|authorization|password)$/.test(key), formatRawJson: context.formatRawJson});
  vm.runInNewContext(source.slice(source.indexOf('function displayCaseValue('), source.indexOf('function selectP01Pane(')), ctx);
  return {ctx, elements};
}
test('case cards preserve reported state and HTTP evidence without inferring PASS', () => {
  const {ctx} = caseHarness();
  const pass = ctx.createCaseCard({status:'PASS', case_id:'normal', observed_status:200, expected_status:200}, 0);
  assert.equal(pass.children[0].children[1].textContent, 'PASS');
  assert.match(pass.children[1].children[1].textContent, /통과!/);
  assert.match(pass.children[1].children[2].textContent, /HTTP 200 \/ 기대 200/);
  const ready = ctx.createCaseCard({outcome:'ready'}, 0);
  assert.equal(ready.className, 'case-card case-neutral');
  assert.equal(ready.children[0].children[1].textContent, 'ready');
});
test('case cards show structured execution logs inside each case', () => {
  const {ctx} = caseHarness();
  const card = ctx.createCaseCard({case_id:'input-kr-rrn', status:'ERR', execution_log:{
    stage:'input', detections:[], candidate_changed:false, delivery_recorded:true,
  }}, 0);
  const texts=[];
  const visit=node=>{if(node.textContent)texts.push(node.textContent);for(const child of node.children||[])visit(child);};
  visit(card);
  assert.ok(texts.includes('실행 로그'));
  assert.ok(texts.some(value=>value.includes('"candidate_changed": false')));
});
test('every P can show actual cases but an enclosing PASS cannot fabricate case success', () => {
  const {ctx, elements} = caseHarness();
  for (let number=1; number<=22; number++) {
    ctx.renderReportedCases({activity_id:`P${String(number).padStart(2,'0')}`, course_verdict:'PASS',result:{cases:[{case_id:'normal'}]}});
    assert.equal(elements['case-results-list'].children[0].className, 'case-card case-neutral');
  }
  ctx.renderReportedCases({course_verdict:'PASS',result:{}});
  assert.equal(elements['case-results'].hidden, true);
  assert.equal(elements['case-results-list'].children.length,0);
});

test('case verification is distinct from native ready or rejected outcomes', () => {
  const {ctx} = caseHarness();
  for (const outcome of ['ready','waiting','rejected']) {
    const card=ctx.createCaseCard({case_verified:true,outcome,calls:1},0);
    assert.equal(card.children[0].children[1].textContent,'PASS');
    assert.match(card.children[1].children[2].textContent,/case_verified=true/);
    assert.ok(card.children[1].children[2].textContent.includes('outcome='+outcome));
  }
  assert.equal(ctx.createCaseCard({case_verified:false,outcome:'ready'},0).children[0].children[1].textContent,'ERR');
});


test('named normal and risk records show their actual model calls without inferred PASS', () => {
  const {ctx, elements} = caseHarness();
  ctx.renderReportedCases({course_verdict:'PASS',result:{normal:{guard_calls:1,main_calls:1},risk:{guard_calls:1,main_calls:0,stop:true,main_capability_status:'closed_unused'}}});
  const cards=elements['case-results-list'].children;
  assert.equal(cards.length,2);
  assert.equal(cards[0].className,'case-card case-neutral');
  assert.match(cards[0].children[1].children[2].textContent,/main_calls=1/);
  assert.match(cards[1].children[1].children[2].textContent,/main_calls=0/);
  assert.match(cards[1].children[1].children[2].textContent,/closed_unused/);
});


test('product records retain assertion scope, native score and investigation evidence', () => {
  const {ctx, elements}=caseHarness();
  const assertion=ctx.createCaseCard({case_id:'H13-RISK',assertion_passed:true},0);
  assert.equal(assertion.children[0].children[1].textContent,'ASSERTION PASS');
  assert.match(assertion.children[1].children[1].textContent,/assertion/);
  const candidate=ctx.createCaseCard({case_id:'PyRIT turn 2',score:1},1);
  assert.equal(candidate.className,'case-card case-neutral');
  assert.match(candidate.children[1].children[2].textContent,/score=1/);
  ctx.renderReportedCases({course_verdict:'PASS',result:{analyses:[{request_id:'r-19',decision:'block',stop_stage:'authorize',downstream_count:0}]}});
  const card=elements['case-results-list'].children[0];
  assert.match(card.children[0].children[0].textContent,/r-19/);
  assert.match(card.children[1].children[1].textContent,/차단 실행/);
  assert.match(card.children[1].children[2].textContent,/downstream_count=0/);
});


test('P22 keeps seven reported approval cases and their native error flags', () => {
  const {ctx, elements}=caseHarness();
  ctx.renderReportedCases({activity_id:'P22',course_verdict:'PASS',result:{normal:{is_error:false},no_approval:{is_error:true},self_approval:{denied:true},changed_args:{is_error:true},expired:{is_error:true},approved:{is_error:false},reuse:{is_error:true}}});
  const cards=elements['case-results-list'].children;
  assert.equal(cards.length,7);
  assert.match(cards[1].children[0].children[0].textContent,/승인 없음/);
  assert.match(cards[2].children[1].children[2].textContent,/denied=true/);
  assert.match(cards[6].children[0].children[0].textContent,/승인 재사용/);
  for (const card of cards) assert.equal(card.className,'case-card case-neutral');
});


test('P19 shows all ten verified analysis checks, including correct damaged-copy denial', () => {
  const {ctx, elements}=caseHarness();
  const checks=Array.from({length:10},(_,i)=>({case_id:'check-'+i,analysis_correct:true,input_kind:i<6?'current_evidence':'damaged_copy',...(i<6?{analysis:{request_id:'r',downstream_count:0}}:{})}));
  ctx.renderReportedCases({activity_id:'P19',result:{analyses:[{request_id:'r'}],checks}});
  const cards=elements['case-results-list'].children;
  assert.equal(cards.length,10);
  assert.equal(cards[0].children[0].children[1].textContent,'ANALYSIS PASS');
  assert.match(cards[9].children[1].children[1].textContent,/손상된 기록/);
});


test('P00 server result updates both completion surfaces without adding a regular mission', () => {
  const elements = {span: {}, small: {}};
  const menu = {classList: {toggle: (_name, value) => {menu.complete = value;}},
    querySelector: name => elements[name], setAttribute: (_name, value) => {menu.label = value;}};
  const ctx = {p00Completed: false, completedPractices: new Map(), byId: () => menu,
    renderHomeProgress: () => {ctx.rendered = ctx.p00Completed;},
    celebrations: [], celebratePractice: id => ctx.celebrations.push(id)};
  vm.runInNewContext(source.slice(source.indexOf('function recordTutorialCompletion('), source.indexOf('function renderPracticeProgress(')), ctx);
  ctx.recordTutorialCompletion({completed: true}, true);
  ctx.recordTutorialCompletion({completed: true}, true);
  assert.deepEqual(ctx.celebrations, ["P00", "P00"]);
  assert.equal(menu.complete, true);
  assert.equal(elements.span.textContent, '🎉');
  assert.equal(ctx.rendered, true);
  assert.equal(ctx.completedPractices.size, 0);
  ctx.recordTutorialCompletion({completed: false});
  assert.equal(menu.complete, false);
  assert.equal(ctx.rendered, false);
  assert.match(source, /tutorialResponse.ok\)\s*\{[\s\S]*?recordTutorialCompletion\(result\)/);
  assert.match(source, /id === "P00" \? p00Completed : completedPractices.has\(id\)/);
});

test('confetti fills the viewport outside the animated completion card', () => {
  const base = path.join(__dirname, '../../llm-security-control-plane/guided-control-center');
  const html = fs.readFileSync(path.join(base, 'index.html'), 'utf8');
  const css = fs.readFileSync(path.join(base, 'app.css'), 'utf8');
  assert.ok(html.indexOf('id="completion-confetti"') < html.indexOf('id="completion-toast"'));
  assert.match(css, /\.completion-confetti \{ position: fixed;.*inset: 0; pointer-events: none/);
  assert.match(css, /100dvh/);
  assert.match(source, /celebrate && p00Completed/);
});

test('the full UI source parses before testing extracted functions', () => {
  assert.doesNotThrow(() => new vm.Script(source));
});

test('P02 preparation and deletion hide the security inspection', () => {
  for (const flag of ['resource_ready', 'resource_deleted']) {
    const nodes = new Map(); const fields = {};
    const byId = id => { if (!nodes.has(id)) nodes.set(id, {hidden: false}); return nodes.get(id); };
    const ctx = {byId, document: {querySelector: selector => byId(selector)},
      rawResponses: new WeakMap(), p01ResultHomes: [], updateDocumentLinks: () => {}, renderResourceProgress: () => {}, showMissionResults: () => {}, renderReportedCases: () => {},
      setText: (id, value) => fields[id] = value};
    vm.runInNewContext(source.slice(source.indexOf('function renderEnvelope('), source.indexOf('function renderError(')), ctx);
    ctx.renderEnvelope({activity_id: 'P02', [flag]: true, task_completed: false});
    assert.equal(nodes.get('.inspection').hidden, true);
    assert.equal(nodes.get('.receipt').hidden, true);
    assert.equal(nodes.get('case-results').hidden, true);
    assert.match(fields['execution-state'], /미채점/);
  }
});

test('resource progress shows server step count and the current resource description', () => {
  const nodes = new Map(); const fields = {};
  const byId = id => { if (!nodes.has(id)) nodes.set(id, {}); return nodes.get(id); };
  const ctx = {byId, setText: (id, value) => fields[id] = value};
  vm.runInNewContext(source.slice(source.indexOf('function renderResourceProgress('), source.indexOf('function renderEnvelope(')), ctx);
  ctx.renderResourceProgress({current: 3, total: 11, title: 'S3 원문 저장소 준비', description: '문서 원문을 보관할 S3 버킷을 준비합니다.'});
  assert.equal(fields['resource-operation-count'], '3 / 11');
  assert.equal(nodes.get('resource-operation-bar').max, 11);
  assert.equal(nodes.get('resource-operation-bar').value, 3);
  assert.equal(fields['resource-operation-label'], 'S3 원문 저장소 준비');
  assert.match(fields['resource-operation-detail'], /문서 원문/);
  ctx.renderResourceProgress({current: 100, total: 11});
  assert.equal(nodes.get('resource-operation-bar').value, 3);
});

function gradingCacheHarness() {
  const saved = new Map();
  const ctx = {practiceGroups: [['P17']], missionOrder: ['P17'], missionResults: new Map(), rawResponses: new WeakMap(),
    displayTutorialGrade: () => {}, sessionStorage: {setItem: (k,v) => saved.set(k,v), getItem: k => saved.get(k)}};
  vm.runInNewContext(source.slice(source.indexOf('function gradingCredentialKey('), source.indexOf('function gradingTimeLabel(')), ctx);
  return {ctx, saved};
}
test('grading reload preserves original nanosecond integers and decimal notation', () => {
  const {ctx, saved} = gradingCacheHarness();
  const raw = '{"activity_id":"P17","timestamp":1790268749899188247,"score":1.00}';
  const payload = JSON.parse(raw);
  ctx.rawResponses.set(payload, raw);
  ctx.cacheGradingResult('P17', payload, Date.now()-1200);
  assert.equal(ctx.rawResponses.get(ctx.missionResults.get('P17')), raw);
  ctx.missionResults.clear();
  ctx.restoreGradingResults();
  const restored = ctx.missionResults.get('P17');
  assert.equal(ctx.rawResponses.get(restored), raw);
  assert.equal(restored._grading_raw_response, undefined);
  assert.ok(saved.get('guided-grading-result-P17').includes('1790268749899188247'));
});
test('grading cache excludes nested and escaped credentials and redacts bearer strings', () => {
  const {ctx, saved} = gradingCacheHarness();
  for (const raw of ['{"activity_id":"P17","nested":{"password":"secret-value"}}',
                     '{"activity_id":"P17","pass\\u0077ord":"secret-value"}',
                     '{"activity_id":"P17","reply":"Bearer secret-value"}']) {
    const payload = JSON.parse(raw);
    ctx.rawResponses.set(payload, raw);
    ctx.cacheGradingResult('P17', payload, Date.now());
    assert.ok(!saved.get('guided-grading-result-P17').includes('secret-value'));
    assert.equal(ctx.rawResponses.get(ctx.missionResults.get('P17')), undefined);
  }
});


test('case details keep null/blank inputs, redact credentials and distinguish defined requests', () => {
  const {ctx}=caseHarness();
  ctx.caseCatalog={P05:{summary:'Dialog 요청 검사',cases:{risk:{request:'정의된 공격'}}}};
  const result=ctx.caseDisplayContext({case_id:'risk',input:null});
  assert.equal(result.input,null);
  assert.equal(result.defined_request,'정의된 공격');
  assert.equal(ctx.displayCaseValue(null),'null');
  assert.equal(ctx.displayCaseValue('   '),'   ');
  const text=ctx.displayCaseValue({approval_token:'credential-value',message:'Bearer abc.secret',query:'실제 검색'});
  assert.ok(!text.includes('credential-value') && !text.includes('abc.secret'));
  assert.ok(text.includes('실제 검색'));
});

test('case comparisons preserve missing actual values and IDs exclude credentials', () => {
  const ctx = {caseCatalog:{},activeProblem:'P07',gradingCredentialKey:key=>/token|secret|password|capability/i.test(key)};
  vm.runInNewContext(source.slice(source.indexOf('function caseComparisons('),source.indexOf('function createCaseCard(')),ctx);
  const rows=ctx.caseComparisons({main_calls:0},{expected_values:{main_calls:0,guard_calls:1}});
  assert.equal(rows[0].actual,0); assert.equal(rows[1].actual,undefined);
  assert.equal(ctx.caseComparisons({token:'private'}, {expected_values:{token:'private'}}).length,0);
  const ids=ctx.caseAnalysisIds({request_id:'request-123',token:{trace_id:'private-123'},child:{trace_id:'trace-123'}});
  assert.deepEqual(Array.from(ids,row=>row.value),['request-123','trace-123']);
});

test('P08 per-case counts use closed case ledger, never normal/risk aggregates', () => {
  const ctx={caseCatalog:{P08:{cases:{a:{expected_values:{main_calls:1,self_check_calls:1}}}}},activeProblem:'P08',gradingCredentialKey:()=>false};
  vm.runInNewContext(source.slice(source.indexOf('function caseComparisons('),source.indexOf('function createCaseCard(')),ctx);
  const payload={result:{normal:{main_calls:2,self_check_calls:2},provider_calls:[{case_id:'a',role:'main'},{case_id:'a',role:'self_check_input'},{case_id:'b',role:'main'}],capabilities:[{case_id:'a',role:'main',status:'completed'},{case_id:'a',role:'self_check_input',status:'completed'}]}};
  assert.deepEqual(Array.from(ctx.caseDisplayContext({case_id:'a'},payload,'P08').case_comparisons,row=>row.actual),[1,1]);
  delete payload.result.capabilities;
  assert.ok(ctx.caseDisplayContext({case_id:'a'},payload,'P08').case_comparisons.every(row=>row.actual===undefined));
});
