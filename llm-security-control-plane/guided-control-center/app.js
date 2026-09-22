"use strict";

const tabNames = [
  "Nova Lite 요청", "Embedding·KB", "Bedrock Guardrail", "NeMo Dialog·Action",
  "입력 안전", "개인정보·출력", "RAG 경계", "Promptfoo 회귀",
  "Garak·PyRIT", "정책 승격", "원시 관측", "사고·경보", "Gateway·Agent"
];
let csrfToken = "";

const byId = (id) => document.getElementById(id);

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
    small.textContent = index === 0 ? "현재 사용 가능" : "다음 구현 단계";
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
  ["preflight", "run", "exercise-start", "hint", "reset"].forEach((id) => {
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

function renderEnvelope(payload) {
  setText("raw", JSON.stringify(payload, null, 2));
  setText("execution-id", payload.execution_id);
  setText("provider-id", payload.evidence?.[0]?.id);
  setText("model-id", payload.result?.model_id);
  setText("forwarded-max", payload.result?.forwarded_parameters?.maxTokens);
  setText("output-tokens", payload.result?.usage?.outputTokens);
  setText("verified-by", payload.verified_by);
  setText("reason", payload.reason);
  setText("next-check", `다음 확인: ${payload.next_check}`);
  setText("execution-state", payload.execution_id || "실행 실패");

  const verdict = byId("verdict");
  verdict.className = `verdict ${(payload.course_verdict || "ERR").toLowerCase()}`;
  verdict.querySelector("strong").textContent = payload.course_verdict || "ERR";
  verdict.querySelector("span").textContent = payload.verified_by || "검증 실패";

  const stages = [{ stage: "control_center", outcome: "completed" }, ...(payload.stage_calls || [])];
  const labels = { control_center: "Control Center", gateway_output_limit: "Gateway Limit", bedrock_main: "Bedrock Main" };
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
byId("run").addEventListener("click", () => execute("/api/labs/01-nova/run", {
  prompt: byId("prompt").value,
  max_output_tokens: Number(byId("max-tokens").value),
  run_kind: byId("run-kind").value
}));
byId("exercise-start").addEventListener("click", async () => {
  try {
    const result = await request("/api/labs/01-nova/exercise/start");
    setText("exercise-copy", `${result.scenario} 성공 조건: ${result.success_condition}`);
    byId("run-kind").value = "bounded";
  } catch (error) { renderError(error); }
});
byId("hint").addEventListener("click", async () => {
  try { setText("exercise-copy", (await request("/api/labs/01-nova/exercise/hint")).hint); }
  catch (error) { renderError(error); }
});
byId("reset").addEventListener("click", async () => {
  try {
    const result = await request("/api/labs/01-nova/exercise/reset");
    setText("exercise-copy", result.message);
    byId("max-tokens").value = "512";
    byId("run-kind").value = "observe";
  } catch (error) { renderError(error); }
});

bootstrap().catch(renderError);
