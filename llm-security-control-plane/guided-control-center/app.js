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

function renderTabs() {
  const tabs = byId("tabs");
  tabNames.forEach((name, index) => {
    const button = document.createElement("button");
    button.type = "button";
    const implemented = index <= 1 || index === 12;
    button.className = index === 0 ? "tab active" : implemented ? "tab" : "tab locked";
    button.disabled = !implemented;
    button.dataset.tabIndex = String(index);
    const number = document.createElement("span");
    number.textContent = String(index + 1).padStart(2, "0");
    const copy = document.createElement("div");
    const strong = document.createElement("strong");
    strong.textContent = name;
    const small = document.createElement("small");
    small.textContent = index === 0 ? "H01 · 강사와 함께" : index === 1 ? "H02 · 강사와 함께" : index === 12 ? "H22 · 강사와 함께" : "다음 구현 단계";
    copy.append(strong, small);
    button.append(number, copy);
    if (implemented) button.addEventListener("click", () => selectTab(index));
    tabs.append(button);
  });
}

function selectTab(index) {
  activeTab = index;
  document.querySelectorAll(".tab").forEach((tab) => {
    tab.classList.toggle("active", Number(tab.dataset.tabIndex) === index);
  });
  byId("h01-work").hidden = index !== 0;
  byId("h02-work").hidden = index !== 1;
  byId("h22-work").hidden = index !== 12;
  const h22 = index === 12;
  setText("current-station", `${String(index + 1).padStart(2, "0")} / 13`);
  setText("current-station-name", index === 0 ? "Nova Lite 요청 경로" : index === 1 ? "Embedding·Knowledge Base" : "MCP Tool 승인 경계");
  setText("activity-label", `HANDS-ON · ${index === 0 ? "H01" : index === 1 ? "H02" : "H22"}`);
  setText("activity-title", index === 0 ? "Bedrock Gateway 만들기" : index === 1 ? "원문과 Knowledge Base 연결하기" : "MCP Tool exact-call 승인 만들기");
  setText("provider-label", index === 0 ? "PROVIDER" : index === 1 ? "TITAN REQUEST" : "TOOL CATALOG");
  setText("model-label", index === 0 ? "MODEL" : index === 1 ? "EMBED MODEL" : "PROTOCOL");
  setText("requested-label", h22 ? "EFFECT ORDER" : index === 0 ? "REQUESTED" : "OBJECT KEY");
  setText("effective-label", h22 ? "SERVER" : index === 0 ? "EFFECTIVE" : "DIMENSION");
  setText("output-label", h22 ? "EFFECTS" : index === 0 ? "OUTPUT TOKENS" : "DATA SOURCE");
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
  ["preflight", "verify", "chat-send", "h02-provision", "h02-verify", "h22-verify"].forEach((id) => {
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
  const h22 = payload.activity_id === "H22";
  setText("provider-id", h22 ? payload.result?.tool_inventory_digest : payload.result?.provider_request_id || payload.result?.aws_request_ids?.[0]);
  setText("model-id", h22 ? payload.result?.protocol_version : payload.result?.model_id || payload.result?.embedding_model_id);
  setText("requested-max", h22 ? payload.result?.effect_counts?.join("→") : h02 ? payload.result?.object_key || payload.result?.source_prefix : payload.result?.requested_max_output_tokens);
  setText("forwarded-max", h22 ? payload.result?.server_id : h02 ? payload.result?.embedding_dimension || payload.result?.dimensions : payload.result?.forwarded_parameters?.maxTokens);
  setText("output-tokens", h22 ? payload.result?.verified_effects?.effects : h02 ? payload.result?.data_source_id : payload.result?.usage?.outputTokens);
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
