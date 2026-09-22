"use strict";

const tabNames = [
  "Nova Lite 요청", "Embedding·KB", "Bedrock Guardrail", "NeMo Dialog·Action",
  "입력 안전", "개인정보·출력", "RAG 경계", "Promptfoo 회귀",
  "Garak·PyRIT", "정책 승격", "원시 관측", "사고·경보", "Gateway·Agent"
];
let csrfToken = "";
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
    button.className = index === 0 ? "tab active" : "tab locked";
    button.disabled = index !== 0;
    const number = document.createElement("span");
    number.textContent = String(index + 1).padStart(2, "0");
    const copy = document.createElement("div");
    const strong = document.createElement("strong");
    strong.textContent = name;
    const small = document.createElement("small");
    small.textContent = index === 0 ? "H01 · 강사와 함께" : "다음 구현 단계";
    copy.append(strong, small);
    button.append(number, copy);
    tabs.append(button);
  });
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
  ["preflight", "verify", "chat-send"].forEach((id) => {
    byId(id).disabled = busy;
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
  setText("provider-id", payload.result?.provider_request_id);
  setText("model-id", payload.result?.model_id);
  setText("requested-max", payload.result?.requested_max_output_tokens);
  setText("forwarded-max", payload.result?.forwarded_parameters?.maxTokens);
  setText("output-tokens", payload.result?.usage?.outputTokens);
  setText("policy-digest", payload.result?.policy_digest?.slice(0, 12));
  setText("verified-by", payload.verified_by);
  setText("reason", payload.reason);
  setText("next-check", `다음 확인: ${payload.next_check}`);
  setText("execution-state", payload.execution_id || "실행 실패");

  const verdict = byId("verdict");
  verdict.className = `verdict ${(payload.course_verdict || "ERR").toLowerCase()}`;
  verdict.querySelector("strong").textContent = payload.course_verdict || "ERR";
  verdict.querySelector("span").textContent = payload.verified_by || "검증 실패";

  const stages = [{ stage: "control_center", outcome: "completed" }, ...(payload.stage_calls || [])];
  const labels = { control_center: "Control Center", student_output_policy: "Student Policy", bedrock_main: "Bedrock Main" };
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
}

byId("preflight").addEventListener("click", () => execute("/api/provider-preflight"));
byId("verify").addEventListener("click", () => execute("/api/hands-on/H01/verify"));
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
