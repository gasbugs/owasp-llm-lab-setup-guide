"use strict";

const tabNames = [
  "Nova Lite 요청", "Embedding·KB", "Bedrock Guardrail", "NeMo Dialog·Action",
  "입력 안전", "개인정보·출력", "RAG 경계", "Promptfoo 회귀",
  "Garak·PyRIT", "정책 승격", "원시 관측", "사고·경보", "Gateway·Agent"
];
let csrfToken = "";
let activeTab = 0;
const rawResponses = new WeakMap();
const themePreference = window.matchMedia("(prefers-color-scheme: dark)");
const themeModes = ["system", "light", "dark"];

const byId = (id) => document.getElementById(id);

function readThemeMode() {
  try {
    const saved = localStorage.getItem("guided-theme-mode");
    return themeModes.includes(saved) ? saved : "system";
  } catch {
    return "system";
  }
}

function applyTheme(mode) {
  const resolved = mode === "system" ? (themePreference.matches ? "dark" : "light") : mode;
  document.documentElement.dataset.theme = resolved;
  document.documentElement.dataset.themeMode = mode;
  document.querySelectorAll(".theme-choice").forEach((choice) => {
    choice.setAttribute("aria-pressed", String(choice.dataset.themeChoice === mode));
  });
}

function saveThemeMode(mode) {
  try {
    if (mode === "system") localStorage.removeItem("guided-theme-mode");
    else localStorage.setItem("guided-theme-mode", mode);
  } catch {
    // 저장할 수 없는 브라우저에서도 현재 탭의 테마 전환은 유지한다.
  }
}

function setText(id, value) {
  byId(id).textContent = value === undefined || value === null ? "—" : String(value);
}

function closeActionTips(except = null) {
  document.querySelectorAll(".action-control").forEach((control) => {
    if (control !== except) {
      control.classList.add("tip-dismissed");
    }
  });
}

function bindActionTips() {
  document.querySelectorAll(".action-control > button[aria-describedby]").forEach((trigger) => {
    const control = trigger.closest(".action-control");
    const show = () => {
      closeActionTips(control);
      control.classList.remove("tip-dismissed");
    };
    trigger.addEventListener("focus", show);
    control.addEventListener("mouseenter", show);
    trigger.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        closeActionTips();
      }
    });
  });
  document.addEventListener("click", (event) => {
    if (!event.target.closest(".action-control")) closeActionTips();
  });
}

function renderTabs() {
  const tabs = byId("tabs");
  tabNames.forEach((name, index) => {
    const button = document.createElement("button");
    button.type = "button";
    const implemented = true;
    button.className = index === 0 ? "tab active" : implemented ? "tab" : "tab locked";
    button.disabled = !implemented;
    button.dataset.tabIndex = String(index);
    const number = document.createElement("span");
    number.textContent = String(index + 1).padStart(2, "0");
    const copy = document.createElement("div");
    const strong = document.createElement("strong");
    strong.textContent = name;
    const small = document.createElement("small");
    small.textContent = ["P01","P02·P03","P04","P05·P06","P07·P08","P09·P10","P11·P12","P13","P14·P15","P16","P17·P18","P19·P20","P21·P22"][index] + " · 직접 작성";
    copy.append(strong, small);
    button.append(number, copy);
    if (implemented) button.addEventListener("click", () => selectTab(index));
    tabs.append(button);
  });
}

function selectTab(index) {
  closeActionTips();
  activeTab = index;
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.toggle("active", Number(tab.dataset.tabIndex) === index);
  });
  byId("h01-work").hidden = index !== 0;
  byId("h02-work").hidden = index !== 1;
  byId("h04-work").hidden = index !== 2;
  byId("h05-work").hidden = index !== 3;
  byId("h07-work").hidden = index !== 4;
  byId("h08-work").hidden = index !== 4;
  byId("h09-work").hidden = index !== 5;
  byId("h10-work").hidden = index !== 5;
  byId("h11-work").hidden = index !== 6;
  byId("h12-work").hidden = index !== 6;
  byId("h13-work").hidden = index !== 7;
  byId("h14-work").hidden = index !== 8; byId("h15-work").hidden = index !== 8;
  byId("h16-work").hidden = index !== 9;
  byId("h17-work").hidden = index !== 10; byId("h18-work").hidden = index !== 10;
  byId("h19-work").hidden = index !== 11; byId("h20-work").hidden = index !== 11;
  byId("h21-work").hidden = index !== 12;
  byId("h22-work").hidden = index !== 12;
  const h09 = index === 5;
  const h22 = index === 12;
  setText("current-station", `${String(index + 1).padStart(2, "0")} / 13`);
  const activityIds=["P01","P02·P03","P04","P05·P06","P07·P08","P09·P10","P11·P12","P13","P14·P15","P16","P17·P18","P19·P20","P21·P22"];
  byId("task-completion").hidden = true;
  byId("task-completion").textContent = "";
  const stationNames=["Nova Lite 요청 경로","Embedding·Knowledge Base","Bedrock 관리형 Guardrail","NeMo Dialog Rail·Action","NeMo 입력 안전","Presidio·출력 Rail","RAG 인증·출처 경계","Promptfoo 회귀 Test","Garak·PyRIT 탐색","정책 승격","원시 관측","사고·경보","Agent·MCP 실행 경계"];
  const activityTitles=["Bedrock Gateway 만들기","원문 저장과 현재 검색 연결하기","관리형 Guardrail을 Nova Lite에 연결하기","한국어 Dialog Rail과 Python Action 만들기","위험 입력을 Main Model 전에 멈추기","개인정보와 위험한 출력이 밖으로 나가기 전에 멈추기","RAG 권한과 Application 단일 진입점 만들기","Promptfoo 회귀 Test 작성하기","Red Team 후보를 실제 영향으로 재확인하기","검증된 정책만 승격하기","Log·Trace·Metric 원시 신호 연결하기","사고 조사와 경보 수명주기 확인하기","Agent 실행 정책과 MCP 승인 만들기"];
  setText("current-station-name",stationNames[index]); setText("activity-label",`PRACTICE · ${activityIds[index]}`); setText("activity-title",activityTitles[index]);
  setText("provider-label", h09 ? "SOURCE" : index === 0 ? "PROVIDER" : index === 1 ? "TITAN REQUEST" : index === 2 ? "AWS REQUEST" : index === 3 ? "EVALUATION" : "TOOL CATALOG");
  setText("model-label", h09 ? "FRAMEWORK" : index === 0 ? "MODEL" : index === 1 ? "EMBED MODEL" : index === 2 ? "GUARDRAIL" : index === 3 ? "FRAMEWORK" : "PROTOCOL");
  setText("requested-label", h09 ? "ENTITIES" : h22 ? "EFFECT ORDER" : index === 0 ? "REQUESTED" : index === 1 ? "OBJECT KEY" : index === 3 ? "SAMPLES" : "ACTION");
  setText("effective-label", h09 ? "DELIVERIES" : h22 ? "SERVER" : index === 0 ? "EFFECTIVE" : index === 1 ? "DIMENSION" : index === 3 ? "EVAL ERRORS" : "STOP REASON");
  setText("output-label", h09 ? "RAW RISK" : h22 ? "EFFECTS" : index === 0 ? "OUTPUT TOKENS" : index === 1 ? "DATA SOURCE" : index === 3 ? "RISK BOT MESSAGE" : "OUTPUT");
}

function renderOfficialUis(items) {
  const nav = byId("official-uis");
  nav.replaceChildren();
  items.forEach((item) => {
    const link = document.createElement("a");
    link.className = "official-link";
    link.href = item.browser_url;
    link.target = "_blank";
    link.rel = "noopener noreferrer";
    const status = document.createElement("span");
    status.className = `status ${item.status}`;
    status.textContent = item.status.toUpperCase();
    const name = document.createElement("strong");
    name.textContent = item.name;
    const boundary = document.createElement("small");
    boundary.textContent = item.boundary;
    link.append(status, name, boundary);
    nav.append(link);
  });
}

function formatRawJson(text) {
  // Keep number tokens intact: nanosecond timestamps exceed JS integer precision.
  const tokens = text.match(/"(?:\\.|[^"\\])*"|[{}\[\],:]|[^\s{}\[\],:]+/g) || [];
  let depth = 0;
  let formatted = "";
  const newline = () => "\n" + "  ".repeat(depth);
  tokens.forEach((token, index) => {
    if (token === "{" || token === "[") {
      formatted += token;
      depth += 1;
      if (tokens[index + 1] !== (token === "{" ? "}" : "]")) formatted += newline();
    } else if (token === "}" || token === "]") {
      depth -= 1;
      if (tokens[index - 1] !== (token === "}" ? "{" : "[")) formatted += newline();
      formatted += token;
    } else if (token === ",") formatted += token + newline();
    else if (token === ":") formatted += ": ";
    else formatted += token;
  });
  return formatted;
}

async function request(path, body = undefined) {
  const options = { method: "POST", headers: { "X-CSRF-Token": csrfToken } };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const text = await response.text();
  const payload = JSON.parse(text);
  if (payload !== null && typeof payload === "object") rawResponses.set(payload, formatRawJson(text));
  if (!response.ok) {
    const error = new Error(JSON.stringify(payload));
    error.detail = payload.detail;
    throw error;
  }
  return payload;
}

function setBusy(busy) {
  ["preflight", "verify", "chat-send", "h02-provision", "h02-verify", "h03-provision", "h03-verify", "h04-provision", "h04-verify", "h05-verify", "h06-verify", "h07-verify", "h08-verify", "h09-verify", "h10-verify", "h11-verify", "h12-verify", "h13-verify", "h14-verify", "h15-verify", "h16-verify", "h17-verify", "h18-verify", "h19-verify", "h20-verify", "h21-verify", "h22-verify"].forEach((id) => {
    if (byId(id)) byId(id).disabled = busy;
  });
  if (busy) {
    setText("execution-state", "새 실행을 기다리는 중");
    document.querySelectorAll(".gate").forEach((gate) => {
      gate.className = "gate running";
      gate.querySelector("small").textContent = "실행 중";
    });
  }
}

function appendChatMessage(role, text) {
  const message = document.createElement("div");
  message.className = `chat-message ${role}`;
  const label = document.createElement("b");
  label.textContent = role === "user" ? "YOU" : "MODEL";
  const copy = document.createElement("p");
  copy.textContent = text;
  message.append(label, copy);
  byId("chat-transcript").append(message);
  message.scrollIntoView({ block: "nearest" });
}

async function sendChat(event) {
  event.preventDefault();
  const prompt = byId("chat-input").value.trim();
  if (!prompt) return;
  appendChatMessage("user", prompt);
  byId("chat-send").disabled = true;
  setText("chat-meta", "현재 수강생 앱과 Nova Lite를 호출하는 중입니다.");
  try {
    const payload = await request("/api/practice/P01/chat", { prompt });
    appendChatMessage("assistant", payload.result.response_text);
    setText(
      "chat-meta",
      `requested ${payload.result.requested_max_output_tokens} → effective ${payload.result.effective_max_output_tokens} · output ${payload.result.usage.outputTokens} · provider ${payload.result.provider_request_id}`,
    );
  } catch (error) {
    appendChatMessage("assistant", "모델 응답을 받지 못했습니다.");
    setText("chat-meta", error.message);
  } finally {
    byId("chat-send").disabled = false;
  }
}

function p03Summary(result) {
  return {
    provider: ['검사 방식', ({aws: 'AWS + 합성 경계 사례', contract: '합성 사례'})[result?.provider_mode]],
    model: ['확인한 코드', result?.source_digest?.slice(0, 12)],
    requested: ['대조한 사례', result?.case_contract_verified === true ? result?.cases?.length : undefined],
    effective: ['검색 결과 확인', result?.case_contract_verified === true ? result?.cases?.filter(c => c.outcome === 'ready').length : undefined],
    output: ['작업·검색 기록', result?.case_contract_verified === true ? '전체 대조됨' : '미확인'],
  };
}

function p04Summary(result) {
  const verified = result?.suite_contract_verified === true;
  return {
    provider: ['검사 방식', ({aws: 'AWS + 합성 경계 사례', contract: '합성 사례'})[result?.provider_mode]],
    model: ['확인한 코드', result?.source_digest?.slice(0, 12)],
    requested: ['대조한 사례', verified ? result?.cases?.length : undefined],
    effective: ['출력 검사 경로', verified ? result?.cases?.filter(c => c.product?.product_result_verified === true).length : undefined],
    output: ['정책·호출 기록', verified ? '전체 대조됨' : '미확인'],
  };
}

function p12Summary(result) {
  return {
    provider: ['검사 묶음', result?.suite_id],
    model: ['확인한 코드', result?.source_digest?.slice(0, 12)],
    requested: ['대조한 사례', result?.cases?.length],
    effective: ['확인한 모델 호출', result?.provider_call_count],
    output: ['확인이 멈춘 사례', result?.failed_case ?? (result?.task_completed === true ? '없음' : '미확인')],
  };
}

function p20Summary(result) {
  const receipt = result?.receipt;
  return {
    provider: ['실행 상태', ({complete: '완료', running: '진행 중', error: '오류'})[receipt?.execution_status]],
    model: ['요청 단계', ({prepare: '준비', normal: '정상 대조', risk: '거부 요청', recovery: '정상 조회 유지'})[receipt?.phase]],
    requested: ['처리 요청', receipt?.cases?.length],
    effective: ['관측 종료', receipt?.closed === true ? '종료' : receipt?.closed === false ? '미종료' : undefined],
    output: ['경보 확인', result?.alert_identity ? '발생·해제 대조됨' : '미확인'],
  };
}

function renderEnvelope(payload) {
  setText("raw", rawResponses.get(payload) ?? JSON.stringify(payload, null, 2));
  if (['P03', 'P04'].includes(payload.activity_id) && payload.resource_ready === true) {
    const preparation = payload.preparation;
    const binding = preparation?.resources?.binding;
    const rows = payload.activity_id === 'P04' ? [
      ['provider', '준비 작업', payload.operation_id, 'provider-id'],
      ['model', 'Guardrail', preparation?.resources?.guardrail?.guardrailIdentifier, 'model-id'],
      ['requested', '설정 버전', preparation?.resources?.guardrail?.guardrailVersion, 'requested-max'],
      ['effective', '준비 상태', preparation?.state, 'forwarded-max'],
      ['output', '설정 식별값', preparation?.resources?.policy_digest?.slice(0, 12), 'output-tokens'],
    ] : [
      ['provider', '준비 작업', payload.operation_id, 'provider-id'],
      ['model', '현재 동기화 작업', binding?.provider_ingestion_job_id, 'model-id'],
      ['requested', 'Knowledge Base', binding?.knowledge_base_id, 'requested-max'],
      ['effective', '동기화 상태', preparation?.evidence?.document?.status, 'forwarded-max'],
      ['output', '원문 위치', preparation?.resources?.source_uris?.[0], 'output-tokens'],
    ];
    for (const [key, label, value, id] of rows) {
      setText(key + '-label', label);
      setText(id, value);
    }
    setText('execution-id', payload.operation_id);
    setText('execution-state', '자원 준비 완료');
    setText('source-digest', null);
    setText('verified-by', '준비 기록 · 과제 미채점');
    setText('reason', payload.activity_id === 'P04' ? '출력 이메일 정책을 준비했습니다. 작성한 함수는 아직 채점하지 않았습니다.' : '원문과 검색 저장소를 준비했습니다. 작성한 함수는 아직 채점하지 않았습니다.');
    setText('next-check', payload.next_check);
    const task = byId('task-completion');
    task.hidden = false;
    task.textContent = `${payload.activity_id} 과제: 미완료`;
    const verdict = byId('verdict');
    verdict.className = 'verdict';
    verdict.querySelector('strong').textContent = '미판정';
    verdict.querySelector('span').textContent = '자원 준비는 보안 판정이 아닙니다';
    byId('belt').replaceChildren();
    return;
  }
  setText("execution-id", payload.execution_id);
  const h02 = ["H02", "P02"].includes(payload.activity_id);
  const h03 = ["H03", "P03"].includes(payload.activity_id);
  const h04 = ["H04", "P04"].includes(payload.activity_id);
  const h05 = ["H05", "P05"].includes(payload.activity_id);
  const h06 = ["H06", "P06"].includes(payload.activity_id);
  const h07 = ["H07", "P07"].includes(payload.activity_id);
  const h08 = ["H08", "P08"].includes(payload.activity_id);
  const h09 = ["H09", "P09"].includes(payload.activity_id);
  const h10 = ["H10", "P10"].includes(payload.activity_id);
  const h11 = ["H11", "P11"].includes(payload.activity_id);
  const h12 = ["H12", "P12"].includes(payload.activity_id);
  const h21 = ["H21", "P21"].includes(payload.activity_id);
  const h22 = ["H22", "P22"].includes(payload.activity_id);
  if (h03) {
    setText("provider-label", "PROVIDER REQUEST");
    setText("model-label", "CURRENT JOB");
    setText("requested-label", "EARLY STATUS");
    setText("effective-label", "FINAL STATUS");
    setText("output-label", "CURRENT SOURCE");
  } else if (h04) {
    setText("provider-label", "AWS REQUEST");
    setText("model-label", "GUARDRAIL");
    setText("requested-label", "ACTION");
    setText("effective-label", "STOP REASON");
    setText("output-label", "OUTPUT");
  } else if (h05) {
    setText("provider-label", "EVALUATION");
    setText("model-label", "FRAMEWORK");
    setText("requested-label", "SAMPLES");
    setText("effective-label", "EVAL ERRORS");
    setText("output-label", "RISK BOT MESSAGE");
  } else if (h06) {
    setText("provider-label", "PROVIDER SUITE");
    setText("model-label", "FRAMEWORK");
    setText("requested-label", "PROVIDER CALLS");
    setText("effective-label", "EFFECTS");
    setText("output-label", "BALANCE");
  } else if (h07) {
    setText("provider-label", "GATEWAY SUITE");
    setText("model-label", "FRAMEWORK");
    setText("requested-label", "GUARD CALLS");
    setText("effective-label", "MAIN CALLS");
    setText("output-label", "RISK STOP");
  } else if (h08) {
    setText("provider-label", "GATEWAY SUITE");
    setText("model-label", "FRAMEWORK");
    setText("requested-label", "SELF-CHECK CALLS");
    setText("effective-label", "MAIN CALLS");
    setText("output-label", "RISK STOPS");
  } else if (h09) {
    setText("provider-label", "DELIVERY SUITE");
    setText("model-label", "PRIVACY ENGINE");
    setText("requested-label", "ENTITIES");
    setText("effective-label", "DELIVERIES");
    setText("output-label", "RAW RISK CASES");
  } else if (h10) {
    setText("provider-label", "GATEWAY SUITE");
    setText("model-label", "OUTPUT RAIL");
    setText("requested-label", "MAIN CALLS");
    setText("effective-label", "OUTPUT CHECKS");
    setText("output-label", "RELEASED MARKERS");
  } else if (h11) {
    setText("provider-label", "TITAN CALLS");
    setText("model-label", "EMBED MODEL");
    setText("requested-label", "DIMENSIONS");
    setText("effective-label", "CASES");
    setText("output-label", "FORBIDDEN CANDIDATES");
  } else if (h12) {
    setText("provider-label", "PIPELINE SUITE");
    setText("model-label", "STAGE ORDER");
    setText("requested-label", "PROTECTED CALLS");
    setText("effective-label", "DIRECT ACCESS");
    setText("output-label", "SIDE EFFECTS");
  } else if (h02) {
    setText("provider-label", "TITAN REQUEST");
    setText("model-label", "EMBED MODEL");
    setText("requested-label", "OBJECT KEY");
    setText("effective-label", "DIMENSIONS");
    setText("output-label", "DATA SOURCE");
  }
  const h05Evaluation = payload.result?.evaluation || payload.result;
  const h05Risk = payload.result?.risk || payload.result?.recovery_case || payload.result?.cases?.find?.((item) => item.case_id === "recovery-risk");
  setText("provider-id", h12 ? payload.execution_id : h11 ? payload.result?.embedding_calls : h09 || h10 ? payload.execution_id : h21 || h22 ? payload.result?.tool_inventory_digest : h07 || h08 ? payload.result?.provider_suite_id || payload.execution_id : h06 ? payload.result?.provider_suite_id || payload.execution_id : h05 ? payload.result?.evaluation_id || h05Evaluation?.evaluation_id : h03 ? payload.result?.final?.provider_request_id || payload.result?.aws_request_ids?.[0] : payload.result?.provider_request_id || payload.result?.aws_request_ids?.[0]);
  setText("model-id", h12 ? payload.result?.declared_stage_order?.join(" → ") : h11 ? payload.result?.embedding_model_id : h09 || h10 ? `${payload.result?.framework} ${payload.result?.framework_version}` : h21 || h22 ? payload.result?.protocol_version : h07 || h08 || h06 ? `${payload.result?.framework || "NeMo Guardrails"} ${payload.result?.framework_version || "0.22.0"}` : h05 ? `${payload.result?.cases?.[0]?.framework || "NeMo Guardrails"} ${payload.result?.cases?.[0]?.framework_version || "0.22.0"}` : h04 ? payload.result?.guardrail_id : h03 ? payload.result?.ingestion_job_id || payload.result?.seed_job_id : payload.result?.model_id || payload.result?.embedding_model_id);
  setText("requested-max", h12 ? payload.result?.protected_call_count : h11 ? payload.result?.dimensions : h10 ? payload.result?.main_calls : h09 ? payload.result?.entities?.join(", ") : h21 ? payload.result?.cases?.length : h22 ? payload.result?.effect_counts?.join("→") : h08 ? payload.result?.self_check_calls : h07 ? payload.result?.content_safety_calls : h06 ? payload.result?.provider_calls?.length ?? payload.result?.provider_call_count : h05 ? h05Evaluation?.processed_samples ?? payload.result?.cases?.length : h04 ? payload.result?.action || payload.result?.output_action : h03 ? payload.result?.early?.job_status || payload.result?.old_source_uri : h02 ? payload.result?.object_key || payload.result?.source_prefix : payload.result?.requested_max_output_tokens);
  setText("forwarded-max", h12 ? payload.result?.direct_access_status : h11 ? payload.result?.cases?.length : h10 ? payload.result?.output_check_calls : h09 ? payload.result?.delivery_count : h21 ? payload.result?.verified_trusted_calls?.length : h22 ? payload.result?.server_id : h07 || h08 ? payload.result?.main_calls : h06 ? payload.result?.effect_count ?? payload.result?.effects?.length : h05 ? `${h05Evaluation?.intent_errors ?? "—"}/${h05Evaluation?.bot_intent_errors ?? "—"}/${h05Evaluation?.bot_message_errors ?? "—"}` : h04 ? payload.result?.stop_reason || payload.result?.status : h03 ? payload.result?.job_status || payload.result?.status : h02 ? payload.result?.embedding_dimension || payload.result?.dimensions : payload.result?.forwarded_parameters?.maxTokens);
  setText("output-tokens", h12 ? payload.result?.direct_side_effects : h11 ? payload.result?.forbidden_candidate_cases?.length : h10 ? payload.result?.browser_released_risk_markers : h09 ? payload.result?.raw_risk_cases?.length : h21 ? payload.result?.verified_provider_calls?.length : h22 ? payload.result?.verified_effects?.effects : h08 ? payload.result?.risk?.stops : h07 ? payload.result?.risk?.stop : h06 ? payload.result?.balance : h05 ? h05Risk?.bot_message : h04 ? payload.result?.output_text || payload.result?.guardrail_version : h03 ? payload.result?.final?.source_uris?.[0] || payload.result?.current_source_uri : h02 ? payload.result?.data_source_id : payload.result?.usage?.outputTokens);
  setText("source-digest", payload.result?.source_digest?.slice(0, 12));
  if (payload.activity_id === "P02" && payload.contract_version === "p02-document-v1") {
    const connection = payload.result?.resource_evidence?.after?.binding;
    setText("provider-label", "검사 묶음");
    setText("provider-id", payload.execution_id);
    setText("model-label", "임베딩 모델");
    setText("model-id", connection?.embedding_model_id);
    setText("requested-label", "확인한 사례");
    setText("requested-max", payload.result?.case_contract_verified ? payload.result?.cases?.length : null);
    setText("effective-label", "벡터 차원");
    setText("forwarded-max", payload.result?.embedding_dimension);
    setText("output-label", "연결한 Data Source");
    setText("output-tokens", connection?.data_source_id);
  }
  if (['P20', 'P12', 'P03', 'P04'].includes(payload.activity_id)) {
    const ids = {provider: 'provider-id', model: 'model-id', requested: 'requested-max',
                 effective: 'forwarded-max', output: 'output-tokens'};
    const summary = payload.activity_id === 'P04' ? p04Summary(payload.result) : payload.activity_id === 'P03' ? p03Summary(payload.result) : payload.activity_id === 'P12' ? p12Summary(payload.result) : p20Summary(payload.result);
    for (const [key, [label, value]] of Object.entries(summary)) {
      setText(key + '-label', label);
      setText(ids[key], value);
    }
  }
  setText("verified-by", payload.verified_by);
  setText("reason", payload.reason);
  setText("next-check", `다음 확인: ${payload.next_check}`);
  setText("execution-state", payload.execution_id || "실행 실패");

  const verdict = byId("verdict");
  const taskCompletion = byId("task-completion");
  taskCompletion.hidden = typeof payload.task_completed !== "boolean";
  taskCompletion.textContent = taskCompletion.hidden ? "" : `${payload.activity_id} 과제: ${payload.task_completed ? "완료" : "미완료"}`;
  verdict.className = `verdict ${(payload.course_verdict || "ERR").toLowerCase()}`;
  verdict.querySelector("strong").textContent = payload.course_verdict || "ERR";
  verdict.querySelector("span").textContent = payload.verified_by || "검증 실패";

  const stages = [{ stage: "control_center", outcome: "completed" }, ...(payload.stage_calls || [])];
  const labels = {
    control_center: "Control Center", learner_gateway: "Learner Gateway", bedrock_main: "Bedrock Main",
    learner_document_app: "Learner Document App", bedrock_titan: "Titan Embeddings",
    s3_source: "S3 Source", s3_vector_index: "S3 Vector Index", knowledge_base: "Knowledge Base",
    h03_s3_source: "P03 S3 Source", h03_knowledge_base: "P03 Knowledge Base",
    learner_sync_app: "Learner Sync App", knowledge_base_ingestion: "KB Ingestion",
    early_retrieval: "Early Retrieval", current_retrieval: "Current Retrieval",
    learner_guardrail_app: "Learner Guardrail App", apply_guardrail: "ApplyGuardrail",
    bedrock_guardrail: "Bedrock Guardrail", bedrock_main_with_guardrail: "Nova Lite + Guardrail",
    learner_dialog_rail: "Learner Dialog Rail", learner_nemo_dialog: "Learner Dialog Rail",
    nemo_dialog: "NeMo Dialog Rail", recovery_dialog_policy: "Recovery Policy",
    topical_evaluation: "Topical Evaluation", nemo_topical_evaluation: "Topical Evaluation",
    learner_nemo_action: "Learner Python Action", action_policy: "Action Allowlist",
    synthetic_action_provider: "Synthetic Action Provider", provider_effect_ledger: "Provider Effect Ledger",
    learner_content_safety: "Learner Content Safety", content_safety_input: "Content Safety Input",
    content_safety_ledger: "Content Safety Ledger",
    learner_self_check_input: "Learner Self-check", self_check_input: "Self-check Input",
    self_check_input_ledger: "Self-check Ledger", h08_provider_ledger: "Self-check Ledger",
    presidio_analyzer: "Presidio Analyzer", presidio_anonymizer: "Presidio Anonymizer",
    h09_delivery_sink: "Delivery Sink",
    main_model: "Main Model", self_check_output: "Self-check Output", browser_release: "Browser Release",
    authenticate: "Authenticate", provenance_filter: "Provenance Filter",
    titan_embedding: "Titan Embeddings", vector_retrieval: "Vector Retrieval",
    application_entry: "Application Entry", protected_services: "Protected Services",
    direct_access: "Direct Access",
    agent_host: "Agent Host", model_provider: "Model Provider", mcp_tools: "MCP Tools",
    mcp_host: "MCP Host", mcp_server: "MCP Server", training_effect: "Training Effect",
  };
  const belt = byId("belt");
  belt.replaceChildren();
  stages.forEach((stage) => {
    const gate = document.createElement("div");
    gate.className = `gate ${payload.course_verdict === "PASS" ? "pass" : payload.course_verdict?.toLowerCase() || "err"}`;
    const title = document.createElement("b");
    title.textContent = labels[stage.stage] || stage.stage;
    const outcome = document.createElement("small");
    outcome.textContent = stage.outcome;
    gate.append(title, outcome);
    belt.append(gate);
  });
}

function renderError(error) {
  const payload = { course_verdict: "ERR", reason: error.message, next_check: "서비스 상태와 원시 오류를 확인합니다.", stage_calls: [] };
  if (/^P\d{2}$/.test(error.detail?.activity_id || "") && error.detail.task_completed === false) {
    Object.assign(payload, error.detail, { course_verdict: "ERR", security_verdict: "ERR", task_completed: false });
  }
  renderEnvelope(payload);
}

async function execute(path, body) {
  setBusy(true);
  byId("task-completion").hidden = true;
  try {
    renderEnvelope(await request(path, body));
  } catch (error) {
    renderError(error);
  } finally {
    setBusy(false);
  }
}

async function bootstrap() {
  renderTabs();
  bindActionTips();
  const response = await fetch("/api/bootstrap");
  if (!response.ok) throw new Error("세션을 시작하지 못했습니다.");
  const payload = await response.json();
  csrfToken = payload.csrf_token;
  renderOfficialUis(payload.official_uis);
  selectTab(0);
}

byId("preflight").addEventListener("click", () => execute("/api/provider-preflight"));
byId("verify").addEventListener("click", () => execute("/api/practice/P01/verify"));
byId("h02-provision").addEventListener("click", () => execute("/api/practice/P02/provision"));
byId("h02-verify").addEventListener("click", () => execute("/api/practice/P02/verify"));
byId("h03-provision").addEventListener("click", () => execute("/api/practice/P03/provision"));
byId("h03-verify").addEventListener("click", () => execute("/api/practice/P03/verify"));
byId("h04-provision").addEventListener("click", () => execute("/api/practice/P04/provision"));
byId("h04-verify").addEventListener("click", () => execute("/api/practice/P04/verify"));
byId("h05-verify").addEventListener("click", () => execute("/api/practice/P05/verify"));
byId("h06-verify").addEventListener("click", () => execute("/api/practice/P06/verify"));
byId("h07-verify").addEventListener("click", () => execute("/api/practice/P07/verify"));
byId("h08-verify").addEventListener("click", () => execute("/api/practice/P08/verify"));
byId("h09-verify").addEventListener("click", () => execute("/api/practice/P09/verify"));
byId("h10-verify").addEventListener("click", () => execute("/api/practice/P10/verify"));
byId("h11-verify").addEventListener("click", () => execute("/api/practice/P11/verify"));
byId("h12-verify").addEventListener("click", () => execute("/api/practice/P12/verify"));
byId("h13-verify").addEventListener("click", () => execute("/api/practice/P13/verify"));
for (let number = 14; number <= 20; number += 1) byId(`h${number}-verify`).addEventListener("click", () => execute(`/api/practice/P${number}/verify`));
byId("h21-verify").addEventListener("click", () => execute("/api/practice/P21/verify"));
byId("h22-verify").addEventListener("click", () => execute("/api/practice/P22/verify"));
byId("chat-form").addEventListener("submit", sendChat);
document.querySelectorAll(".theme-choice").forEach((choice) => {
  choice.addEventListener("click", () => {
    const mode = choice.dataset.themeChoice;
    saveThemeMode(mode);
    applyTheme(mode);
  });
});
themePreference.addEventListener("change", () => {
  if (document.documentElement.dataset.themeMode === "system") applyTheme("system");
});

applyTheme(readThemeMode());
bootstrap().catch(renderError);
