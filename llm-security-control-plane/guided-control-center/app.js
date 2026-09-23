"use strict";

const tabNames = [
  "Nova Lite 요청", "Embedding·KB", "Bedrock Guardrail", "NeMo Dialog·Action",
  "입력 안전", "개인정보·출력", "RAG 경계", "Promptfoo 회귀",
  "Garak·PyRIT", "정책 승격", "원시 관측", "사고·경보", "Gateway·Agent"
];
let csrfToken = "";
let activeTab = 0;
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
  document.querySelectorAll(".action-control.tip-open").forEach((control) => {
    if (control !== except) {
      control.classList.remove("tip-open");
      control.querySelector(".help-trigger")?.setAttribute("aria-expanded", "false");
    }
  });
}

function bindActionTips() {
  document.querySelectorAll(".help-trigger").forEach((trigger) => {
    trigger.addEventListener("click", (event) => {
      event.stopPropagation();
      const control = trigger.closest(".action-control");
      const open = !control.classList.contains("tip-open");
      closeActionTips(control);
      control.classList.toggle("tip-open", open);
      trigger.setAttribute("aria-expanded", String(open));
    });
    trigger.addEventListener("keydown", (event) => {
      if (event.key === "Escape") {
        closeActionTips();
        trigger.focus();
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
    const implemented = index <= 4 || index === 12;
    button.className = index === 0 ? "tab active" : implemented ? "tab" : "tab locked";
    button.disabled = !implemented;
    button.dataset.tabIndex = String(index);
    const number = document.createElement("span");
    number.textContent = String(index + 1).padStart(2, "0");
    const copy = document.createElement("div");
    const strong = document.createElement("strong");
    strong.textContent = name;
    const small = document.createElement("small");
    small.textContent = index === 0 ? "H01 · 직접 작성" : index === 1 ? "H02·H03 · 직접 작성" : index === 2 ? "H04 · 직접 작성" : index === 3 ? "H05·H06 · 직접 작성" : index === 4 ? "H07 · 직접 작성 · H08 준비 중" : index === 12 ? "H21·H22 · 직접 작성" : "다음 구현 단계";
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
  byId("h21-work").hidden = index !== 12;
  byId("h22-work").hidden = index !== 12;
  const h22 = index === 12;
  setText("current-station", `${String(index + 1).padStart(2, "0")} / 13`);
  setText("current-station-name", index === 0 ? "Nova Lite 요청 경로" : index === 1 ? "Embedding·Knowledge Base" : index === 2 ? "Bedrock 관리형 Guardrail" : index === 3 ? "NeMo Dialog Rail·Action" : index === 4 ? "NeMo 입력 안전" : "Agent·MCP 실행 경계");
  setText("activity-label", `HANDS-ON · ${index === 0 ? "H01" : index === 1 ? "H02·H03" : index === 2 ? "H04" : index === 3 ? "H05·H06" : index === 4 ? "H07" : "H21·H22"}`);
  setText("activity-title", index === 0 ? "Bedrock Gateway 만들기" : index === 1 ? "원문 저장과 현재 검색 연결하기" : index === 2 ? "관리형 Guardrail을 Nova Lite에 연결하기" : index === 3 ? "한국어 Dialog Rail과 Python Action 만들기" : index === 4 ? "위험 입력을 Main Model 전에 멈추기" : "Agent 실행 정책과 MCP 승인 만들기");
  setText("provider-label", index === 0 ? "PROVIDER" : index === 1 ? "TITAN REQUEST" : index === 2 ? "AWS REQUEST" : index === 3 ? "EVALUATION" : "TOOL CATALOG");
  setText("model-label", index === 0 ? "MODEL" : index === 1 ? "EMBED MODEL" : index === 2 ? "GUARDRAIL" : index === 3 ? "FRAMEWORK" : "PROTOCOL");
  setText("requested-label", h22 ? "EFFECT ORDER" : index === 0 ? "REQUESTED" : index === 1 ? "OBJECT KEY" : index === 3 ? "SAMPLES" : "ACTION");
  setText("effective-label", h22 ? "SERVER" : index === 0 ? "EFFECTIVE" : index === 1 ? "DIMENSION" : index === 3 ? "EVAL ERRORS" : "STOP REASON");
  setText("output-label", h22 ? "EFFECTS" : index === 0 ? "OUTPUT TOKENS" : index === 1 ? "DATA SOURCE" : index === 3 ? "RISK BOT MESSAGE" : "OUTPUT");
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

async function request(path, body = undefined) {
  const options = { method: "POST", headers: { "X-CSRF-Token": csrfToken } };
  if (body !== undefined) {
    options.headers["Content-Type"] = "application/json";
    options.body = JSON.stringify(body);
  }
  const response = await fetch(path, options);
  const payload = await response.json();
  if (!response.ok) throw new Error(JSON.stringify(payload));
  return payload;
}

function setBusy(busy) {
  ["preflight", "verify", "chat-send", "h02-provision", "h02-verify", "h03-provision", "h03-verify", "h04-provision", "h04-verify", "h05-verify", "h06-verify", "h07-verify", "h21-verify", "h22-verify"].forEach((id) => {
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
    const payload = await request("/api/hands-on/H01/chat", { prompt });
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

function renderEnvelope(payload) {
  setText("raw", JSON.stringify(payload, null, 2));
  setText("execution-id", payload.execution_id);
  const h02 = payload.activity_id === "H02";
  const h03 = payload.activity_id === "H03";
  const h04 = payload.activity_id === "H04";
  const h05 = payload.activity_id === "H05";
  const h06 = payload.activity_id === "H06";
  const h07 = payload.activity_id === "H07";
  const h21 = payload.activity_id === "H21";
  const h22 = payload.activity_id === "H22";
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
  } else if (h02) {
    setText("provider-label", "TITAN REQUEST");
    setText("model-label", "EMBED MODEL");
    setText("requested-label", "OBJECT KEY");
    setText("effective-label", "DIMENSIONS");
    setText("output-label", "DATA SOURCE");
  }
  const h05Evaluation = payload.result?.evaluation || payload.result;
  const h05Risk = payload.result?.risk || payload.result?.recovery_case || payload.result?.cases?.find?.((item) => item.case_id === "recovery-risk");
  setText("provider-id", h21 || h22 ? payload.result?.tool_inventory_digest : h07 ? payload.result?.provider_suite_id || payload.execution_id : h06 ? payload.result?.provider_suite_id || payload.execution_id : h05 ? payload.result?.evaluation_id || h05Evaluation?.evaluation_id : h03 ? payload.result?.final?.provider_request_id || payload.result?.aws_request_ids?.[0] : payload.result?.provider_request_id || payload.result?.aws_request_ids?.[0]);
  setText("model-id", h21 || h22 ? payload.result?.protocol_version : h07 || h06 ? `${payload.result?.framework || "NeMo Guardrails"} ${payload.result?.framework_version || "0.22.0"}` : h05 ? `${payload.result?.cases?.[0]?.framework || "NeMo Guardrails"} ${payload.result?.cases?.[0]?.framework_version || "0.22.0"}` : h04 ? payload.result?.guardrail_id : h03 ? payload.result?.ingestion_job_id || payload.result?.seed_job_id : payload.result?.model_id || payload.result?.embedding_model_id);
  setText("requested-max", h21 ? payload.result?.cases?.length : h22 ? payload.result?.effect_counts?.join("→") : h07 ? payload.result?.content_safety_calls : h06 ? payload.result?.provider_calls?.length ?? payload.result?.provider_call_count : h05 ? h05Evaluation?.processed_samples ?? payload.result?.cases?.length : h04 ? payload.result?.action || payload.result?.output_action : h03 ? payload.result?.early?.job_status || payload.result?.old_source_uri : h02 ? payload.result?.object_key || payload.result?.source_prefix : payload.result?.requested_max_output_tokens);
  setText("forwarded-max", h21 ? payload.result?.verified_trusted_calls?.length : h22 ? payload.result?.server_id : h07 ? payload.result?.main_calls : h06 ? payload.result?.effect_count ?? payload.result?.effects?.length : h05 ? `${h05Evaluation?.intent_errors ?? "—"}/${h05Evaluation?.bot_intent_errors ?? "—"}/${h05Evaluation?.bot_message_errors ?? "—"}` : h04 ? payload.result?.stop_reason || payload.result?.status : h03 ? payload.result?.job_status || payload.result?.status : h02 ? payload.result?.embedding_dimension || payload.result?.dimensions : payload.result?.forwarded_parameters?.maxTokens);
  setText("output-tokens", h21 ? payload.result?.verified_provider_calls?.length : h22 ? payload.result?.verified_effects?.effects : h07 ? payload.result?.risk?.stop : h06 ? payload.result?.balance : h05 ? h05Risk?.bot_message : h04 ? payload.result?.output_text || payload.result?.guardrail_version : h03 ? payload.result?.final?.source_uris?.[0] || payload.result?.current_source_uri : h02 ? payload.result?.data_source_id : payload.result?.usage?.outputTokens);
  setText("source-digest", payload.result?.source_digest?.slice(0, 12));
  setText("verified-by", payload.verified_by);
  setText("reason", payload.reason);
  setText("next-check", `다음 확인: ${payload.next_check}`);
  setText("execution-state", payload.execution_id || "실행 실패");

  const verdict = byId("verdict");
  verdict.className = `verdict ${(payload.course_verdict || "ERR").toLowerCase()}`;
  verdict.querySelector("strong").textContent = payload.course_verdict || "ERR";
  verdict.querySelector("span").textContent = payload.verified_by || "검증 실패";

  const stages = [{ stage: "control_center", outcome: "completed" }, ...(payload.stage_calls || [])];
  const labels = {
    control_center: "Control Center", learner_gateway: "Learner Gateway", bedrock_main: "Bedrock Main",
    learner_document_app: "Learner Document App", bedrock_titan: "Titan Embeddings",
    s3_source: "S3 Source", s3_vector_index: "S3 Vector Index", knowledge_base: "Knowledge Base",
    h03_s3_source: "H03 S3 Source", h03_knowledge_base: "H03 Knowledge Base",
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
  renderEnvelope(payload);
}

async function execute(path, body) {
  setBusy(true);
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
byId("verify").addEventListener("click", () => execute("/api/hands-on/H01/verify"));
byId("h02-provision").addEventListener("click", () => execute("/api/hands-on/H02/provision"));
byId("h02-verify").addEventListener("click", () => execute("/api/hands-on/H02/verify"));
byId("h03-provision").addEventListener("click", () => execute("/api/hands-on/H03/provision"));
byId("h03-verify").addEventListener("click", () => execute("/api/hands-on/H03/verify"));
byId("h04-provision").addEventListener("click", () => execute("/api/hands-on/H04/provision"));
byId("h04-verify").addEventListener("click", () => execute("/api/hands-on/H04/verify"));
byId("h05-verify").addEventListener("click", () => execute("/api/hands-on/H05/verify"));
byId("h06-verify").addEventListener("click", () => execute("/api/hands-on/H06/verify"));
byId("h07-verify").addEventListener("click", () => execute("/api/hands-on/H07/verify"));
byId("h21-verify").addEventListener("click", () => execute("/api/hands-on/H21/verify"));
byId("h22-verify").addEventListener("click", () => execute("/api/hands-on/H22/verify"));
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
