let caseCatalog = {};
let resourceTotals = {};
"use strict";

const tabNames = [
  "AI Gateway 운영", "Embedding·KB", "Bedrock Guardrail", "NeMo Dialog·Action",
  "입력 안전", "개인정보·출력", "RAG 경계", "Promptfoo 회귀",
  "Garak·PyRIT", "정책 승격", "원시 관측", "사고·경보", "Gateway·Agent"
];
const practiceGroups = ["P01", "P23·P02·P03", "P04", "P05·P06", "P07·P08", "P09·P10", "P11·P12", "P13", "P14·P15", "P16", "P17·P18", "P19·P20", "P21·P22"].map(group => group.split("·"));
const educationOrder = [1, 2, 0, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
const menuCategories = [
  {number: "01", title: "Bedrock 모델·Knowledge Base", groups: [1]},
  {number: "02", title: "AWS 관리형 Guardrail", groups: [2]},
  {number: "03", title: "AI Gateway 운영", groups: [0]},
  {number: "04", title: "로컬 Guardrail·RAG", groups: [3, 4, 5, 6]},
  {number: "05", title: "공격 평가·정책 개선", groups: [7, 8, 9]},
  {number: "06", title: "관측·사건 조사", groups: [10, 11]},
  {number: "07", title: "Agent·MCP", groups: [12]},
];
const completedPractices = new Map();
let p00Completed = false;
const recheckPractices = new Map();
const celebratedPractices = new Set();
let celebrationTimer = null;
let progressRequest = 0;
let csrfToken = "";
let adminMode = false;
let adminAnswerPanel = null;
let adminAnswerRequest = 0;
let activeTab = 0;
let activeProblem = "P01";
let sidebarPinned = false;
try { sidebarPinned = localStorage.getItem("guided-sidebar-pinned") === "true"; } catch {}
const rawResponses = new WeakMap();
const missionResults = new Map();
let executionPending = false;
let executionTimer = null;
const themePreference = window.matchMedia("(prefers-color-scheme: dark)");
const themeModes = ["system", "light", "dark"];

const byId = (id) => document.getElementById(id);

function gradingCredentialKey(key) {
  return /^(authorization|access_token|refresh_token|password|csrf_token|p00_submission_token|cookie|credential|credentials|secret|capability|token|aws_access_key_id|aws_secret_access_key|aws_session_token)$/i.test(key);
}

function safeGradingRaw(raw) {
  if (typeof raw !== "string" || raw.length > 1048576) return undefined;
  const sensitive = value => {
    if (typeof value === "string") return /\bBearer\s+[A-Za-z0-9._~-]+/i.test(value);
    if (!value || typeof value !== "object") return false;
    return Object.entries(value).some(([key, item]) => gradingCredentialKey(key) || sensitive(item));
  };
  try { return sensitive(JSON.parse(raw)) ? undefined : raw; } catch { return undefined; }
}

function restoreGradingRaw(result) {
  const raw = safeGradingRaw(result._grading_raw_response);
  delete result._grading_raw_response;
  if (raw !== undefined) rawResponses.set(result, raw);
}

function cacheGradingResult(problem, payload, startedAt) {
  if (problem !== "P00" && !practiceGroups.some(group => group.includes(problem))) return;
  if (payload.resource_ready || payload.resource_deleted || payload.graded === false) return;
  payload._grading_checked_at = new Date().toISOString();
  if (Number.isFinite(startedAt)) payload._grading_elapsed_seconds = Math.max(0, (Date.now() - startedAt) / 1000);
  const serialized = JSON.stringify({...payload, _grading_raw_response: safeGradingRaw(rawResponses.get(payload))}, (key, value) =>
    gradingCredentialKey(key) ? undefined : typeof value === "string"
      ? value.replace(/\bBearer\s+[A-Za-z0-9._~-]+/gi, "Bearer [redacted]") : value);
  const display = JSON.parse(serialized);
  restoreGradingRaw(display);
  if (problem !== "P00") missionResults.set(problem, display);
  try { sessionStorage.setItem(`guided-grading-result-${problem}`, serialized); } catch {}
}

function restoreGradingResults() {
  displayTutorialGrade({completed: false});
  for (const problem of missionOrder) {
    try {
      const saved = sessionStorage.getItem(`guided-grading-result-${problem}`);
      if (!saved) continue;
      const result = JSON.parse(saved);
      if (!result || typeof result !== "object" || Array.isArray(result)) continue;
      restoreGradingRaw(result);
      if (problem === "P00") displayTutorialGrade(result);
      else if (result.activity_id === problem && !result.resource_ready && !result.resource_deleted && result.graded !== false) missionResults.set(problem, result);
    } catch {}
  }
}

function gradingTimeLabel(result) {
  const timestamp = Date.parse(result._grading_checked_at);
  if (!Number.isFinite(timestamp)) return "마지막 검사: 시간 기록 없음";
  const time = new Date(timestamp).toLocaleString("ko-KR", {
    timeZone: "Asia/Seoul", year: "numeric", month: "2-digit", day: "2-digit",
    hour: "2-digit", minute: "2-digit", second: "2-digit", hour12: false,
  });
  const duration = Number.isFinite(result._grading_elapsed_seconds) ? ` · 소요 ${result._grading_elapsed_seconds.toFixed(1)}초` : "";
  return `마지막 검사: ${time} (한국시간)${duration}`;
}

function displayTutorialGrade(result) {
  setText("tutorial-checked-at", gradingTimeLabel(result));
  const cases = byId("tutorial-cases");
  cases.replaceChildren();
  const reported = Array.isArray(result.cases) && result.cases.length ? result.cases : [
    ["JSON 객체 형식", "올바른 JSON 객체"],
    ["필드 이름과 개수", ["message", "max_tokens"]],
    ["질문 문장", "계정 보안을 위한 조언을 한 문장으로 알려 주세요."],
    ["출력 상한의 자료형과 값", {type: "int", value: 64}],
  ].map(([case_id, expected]) => ({case_id, expected, status: result.completed ? "재제출 필요" : "제출 대기"}));
  for (const [index, item] of reported.entries()) cases.append(createCaseCard(caseDisplayContext(item, result, "P00"), index));
  setText("tutorial-result", JSON.stringify(result, null, 2));
  setText("tutorial-grade-status", result.cases?.length
    ? `${result.completed ? "P00 미션 완료!" : "P00 미션 미완료"} ${result.feedback || ""}`
    : result.completed
      ? "P00 완료 기록은 유지됩니다. 케이스별 결과를 확인하려면 왼쪽 명령으로 요청 파일을 다시 제출하고 미션 채점을 누르세요."
      : "왼쪽 명령으로 요청 파일을 제출한 뒤 미션 채점을 누르세요.");
}

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
  const node = byId(id);
  node.textContent = value === undefined || value === null ? "—" : String(value);
  if (["raw", "tutorial-result", "resource-raw", "mission-experience-raw", "h23-chat-raw", "model-connection-raw"].includes(id)) {
    const disclosure = node.closest("details");
    if (disclosure) disclosure.open = false;
  }
}

function missionLabel(problem) {
  const category = menuCategories.find(item => item.groups.some(index => practiceGroups[index].includes(problem)));
  if (!category) return problem;
  const position = category.groups.flatMap(index => practiceGroups[index]).indexOf(problem) + 1;
  return `P${category.number}-${String(position).padStart(2, "0")}`;
}

function applyMissionDisplayLabels() {
  const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
  while (walker.nextNode()) {
    const node = walker.currentNode;
    if (!node.parentElement.closest("pre, code, kbd, script, style")) {
      node.textContent = node.textContent.replace(/\bP\d{2}\b(?!-\d{2})/g, missionLabel);
    }
  }
}

function renderTabs() {
  const tabs = byId("tabs");
  for (const category of menuCategories) {
    const section = document.createElement("details");
    section.className = "mission-category"; section.dataset.category = category.number;
    const storageKey = `guided-category-open-${category.number}`;
    try { section.open = localStorage.getItem(storageKey) === "true"; } catch { section.open = false; }
    section.addEventListener("toggle", () => {
      try { localStorage.setItem(storageKey, String(section.open)); } catch {}
    });
    const heading = document.createElement("summary");
    const code = document.createElement("span"); code.className = "category-number"; code.textContent = category.number;
    const title = document.createElement("span"); title.textContent = category.title;
    const icon = document.createElementNS("http://www.w3.org/2000/svg", "svg");
    icon.setAttribute("viewBox", "0 0 24 24"); icon.setAttribute("aria-hidden", "true");
    const line = document.createElementNS("http://www.w3.org/2000/svg", "path");
    line.setAttribute("d", "m9 6 6 6-6 6"); icon.append(line);
    heading.append(code, title, icon); section.append(heading); tabs.append(section);
  }
  for (const problem of missionOrder.filter(id => id !== "P00")) {
    const index = practiceGroups.findIndex(group => group.includes(problem));
    const button = document.createElement("button");
    button.type = "button"; button.className = "tab";
    button.dataset.tabIndex = String(index); button.dataset.problem = problem;
    button.id = problem === practiceGroups[index][0] ? `practice-tab-${index}` : `practice-menu-${problem}`;
    button.setAttribute("role", "tab"); button.setAttribute("aria-controls", "practice-workbench");
    button.setAttribute("aria-selected", "false"); button.tabIndex = -1;
    button.addEventListener("keydown", handleMissionMenuKey);
    const number = document.createElement("span"); number.textContent = missionLabel(problem);
    const copy = document.createElement("div");
    const strong = document.createElement("strong"); strong.textContent = homeMissions.find(item => item.id === problem).title;
    const small = document.createElement("small"); small.textContent = `${missionLabel(problem)} · ${tabNames[index]}`;
    copy.append(strong, small); button.append(number, copy);
    button.addEventListener("click", () => selectTab(index, problem));
    const category = menuCategories.find(item => item.groups.includes(index));
    tabs.querySelector(`[data-category="${category.number}"]`).append(button);
  }
}

function recordTutorialCompletion(result, celebrate = false) {
  p00Completed = result.completed === true;
  const menu = byId("p00-menu");
  menu.classList.toggle("is-complete", p00Completed);
  menu.querySelector("span").textContent = p00Completed ? "🎉" : "P00";
  menu.querySelector("small").textContent = p00Completed ? "P00 ✓ · 완료" : "P00 · 따라 하기";
  menu.setAttribute("aria-label", `P00 첫 미션 튜토리얼, ${p00Completed ? "완료" : "미완료"}`);
  renderHomeProgress();
  if (celebrate && p00Completed) celebratePractice("P00");
}

function renderPracticeProgress() {
  document.querySelectorAll(".tab[data-tab-index]").forEach(tab => {
    const problem = tab.dataset.problem;
    const complete = completedPractices.has(problem);
    const recheck = recheckPractices.has(problem);
    tab.classList.toggle("is-complete", complete);
    tab.classList.toggle("is-partial", recheck);
    tab.querySelector("span").textContent = complete ? "🎉" : missionLabel(problem);
    tab.querySelector("small").textContent = `${missionLabel(problem)} · ${complete ? "완료" : recheck ? "재검증 필요" : tabNames[Number(tab.dataset.tabIndex)]}`;
    tab.setAttribute("aria-label", `${missionLabel(problem)} ${complete ? "완료" : recheck ? "재검증 필요" : "미완료"}`);
  });
  setText("practice-progress-count", `${completedPractices.size} / 23`);
  byId("practice-progress").value = completedPractices.size;
  renderHomeProgress();
  const history = byId("practice-history");
  history.replaceChildren();
  if (recheckPractices.size) {
    const row = document.createElement("p");
    const problems = [...recheckPractices.keys()].sort();
    row.textContent = `↻ 재검증 필요 ${problems.length}개 · ${problems.join(", ")}`;
    row.title = [...new Set(recheckPractices.values())].join(" · ");
    history.append(row);
  }
}

const homeMissions = [
  "AI 호출 게이트를 지켜라!",
  "문서를 검색의 출발점으로!",
  "옛 문서 말고, 지금 문서를 찾아라!",
  "검사한 정책을 실제 답변에도!",
  "복구 코드를 묻는 상담을 막아라!",
  "조회는 허용! 잔액 변경은 정지!",
  "위험한 입력은 모델 호출 전에!",
  "우리 앱의 업무 규칙을 지켜라!",
  "개인정보는 가리고 전달하라!",
  "모델이 만들었다고 공개해도 될까?",
  "검색 권한은 서버가 결정한다!",
  "모든 요청을 안전한 한 경로로!",
  "발견한 공격을 다시 놓치지 마라!",
  "Garak 탐색, 끝나는 범위를 정하라!",
  "공격 후보, 점수보다 증거!",
  "검증한 정책만 운영으로!",
  "한 요청의 흔적을 남겨라!",
  "흩어진 기록에서 같은 요청 찾기!",
  "사건의 시작부터 끝까지 연결하라!",
  "거부 요청이 생기면 알려라!",
  "Agent의 실행 범위를 지켜라!",
  "승인한 도구 호출만 실행하라!",
  "첫 질문을 Nova Lite까지!",
].map((title, index) => ({id: `P${String(index + 1).padStart(2, "0")}`, title}));
const missionOrder = ["P00", ...educationOrder.flatMap(index => practiceGroups[index])];
homeMissions.unshift({id: "P00", title: "첫 미션 튜토리얼"});
homeMissions.sort((a, b) => missionOrder.indexOf(a.id) - missionOrder.indexOf(b.id));
function renderBreadcrumb(problem) {
  const home = byId("breadcrumb-home");
  const topic = byId("mission-topic");
  const title = problem === "P00" ? byId("tutorial-panel").querySelector(".panel-head h2") : byId("activity-title");
  title.parentElement.prepend(topic);
  byId("mission-topic").hidden = !problem;
  byId("breadcrumb-current").closest("li").hidden = !problem;
  byId("breadcrumb-category").closest("li").hidden = !problem || problem === "P00";
  if (!problem) {
    home.setAttribute("aria-current", "page");
    setText("mission-topic", ""); setText("breadcrumb-current", "");
    return;
  }
  home.removeAttribute("aria-current");
  if (problem === "P00") {
    setText("mission-topic", "사용 안내");
    setText("breadcrumb-current", "P00 · 첫 미션 튜토리얼");
    return;
  }
  const mission = homeMissions.find(item => item.id === problem);
  const category = menuCategories.find(item => item.groups.some(index => practiceGroups[index].includes(problem)));
  setText("mission-topic", category.title);
  setText("breadcrumb-category", `${category.number} ${category.title}`);
  setText("breadcrumb-current", `${missionLabel(problem)} · ${mission.title}`);
}

function renderHomeProgress() {
  const count = completedPractices.size + Number(p00Completed);
  const total = homeMissions.length;
  if (!byId("home-panel").hidden) setText("current-station", `${count} / ${total}`);
  setText("home-completed-value", String(count));
  setText("home-total", String(total));
  setText("home-percent", `${Math.round(count / total * 100)}%`);
  setText("home-remaining", total - count);
  setText("home-recheck", recheckPractices.size);
  byId("home-progress").max = total;
  byId("home-progress").value = count;
  setText("practice-progress-count", `${count} / ${total}`);
  byId("practice-progress").max = total;
  byId("practice-progress").value = count;
  const next = missionOrder.filter(id => id !== "P00").find(id => !completedPractices.has(id));
  setText("home-next", next ? `${missionLabel(next)} ${recheckPractices.has(next) ? "재검증하기" : "시작하기"}` : "미션 목록 보기");
  byId("home-next").dataset.problem = next || "";
  const grid = byId("home-missions");
  grid.replaceChildren();
  for (const {id, title} of homeMissions) {
    const card = document.createElement("button"); card.type = "button"; card.className = "home-mission";
    card.dataset.problem = id;
    const complete = id === "P00" ? p00Completed : completedPractices.has(id);
    const state = complete ? "✓ 완료" : id === "P00" ? "미완료" : recheckPractices.has(id) ? "재검증 필요" : "미완료";
    card.classList.toggle("is-complete", complete);
    card.classList.toggle("needs-recheck", recheckPractices.has(id));
    const number = document.createElement("span"); number.className = "home-mission-id"; number.textContent = missionLabel(id);
    const heading = document.createElement("strong"); heading.textContent = title;
    const status = document.createElement("span"); status.className = "home-mission-status"; status.textContent = state;
    card.setAttribute("aria-label", `${missionLabel(id)} · ${title} · ${state}`);
    card.addEventListener("click", () => {
      if (id === "P00") {
        selectWorkspace("tutorial"); byId("tutorial-panel").focus();
        return;
      }
      selectTab(practiceGroups.findIndex(group => group.includes(id)), id);
      const work = byId(`h${id.slice(1)}-work`);
      work.setAttribute("tabindex", "-1");
      work.focus({preventScroll: true}); work.scrollIntoView({block: "start"});
    });
    card.append(number, heading, status); grid.append(card);
  }
}

async function restorePracticeProgress() {
  const revision = ++progressRequest;
  try {
    const response = await fetch("/api/progress");
    if (!response.ok) throw new Error("progress unavailable");
    const payload = await response.json();
    if (revision !== progressRequest || executionPending) return;
    completedPractices.clear();
    recheckPractices.clear();
    for (const record of payload.records || []) {
      if (!practiceGroups.some(group => group.includes(record.problem))) continue;
      celebratedPractices.add(record.problem);
      if (record.state === "completed") completedPractices.set(record.problem, record.execution);
      else recheckPractices.set(record.problem, record.reason);
    }
    renderPracticeProgress();
    setText("home-progress-note", "현재 실행본에서 검증된 완료 수입니다. 코드를 바꾼 미션은 다시 채점해 완료 상태를 갱신하세요.");
    setText("progress-status", "이 실습 환경에 저장됩니다. ✓ 통과한 실행본 · ↻ 재검증 필요. PC 파일만 고친 상태는 Build·적용 후 확인합니다. 실행본 조회가 없는 문제도 완료 이력은 남지만 재검증이 필요합니다.");
  } catch {
    if (revision !== progressRequest || executionPending) return;
    for (const problem of completedPractices.keys()) {
      recheckPractices.set(problem, "현재 실행본을 확인하지 못했습니다.");
    }
    completedPractices.clear();
    renderPracticeProgress();
    setText("home-progress-note", "완료 기록을 불러오지 못했습니다. 새로고침해 다시 확인하세요.");
    setText("progress-status", "저장된 완료 기록을 불러오지 못했습니다. 기록이 삭제된 것은 아닙니다. 새로고침해 다시 확인하세요.");
  }
}

function dismissCelebration() {
  clearTimeout(celebrationTimer);
  celebrationTimer = null;
  byId("completion-toast").hidden = true;
  byId("completion-confetti").hidden = true;
  byId("completion-confetti").replaceChildren();
}

function playCompletionFanfare() {
  const Audio = window.AudioContext || window.webkitAudioContext;
  if (!Audio) return;
  try {
    const audio = new Audio();
    audio.resume().catch(() => {});
    [523.25, 659.25, 783.99, 1046.5].forEach((frequency, index) => {
      const tone = audio.createOscillator();
      const gain = audio.createGain();
      const start = audio.currentTime + index * .12;
      tone.type = "triangle"; tone.frequency.value = frequency;
      gain.gain.setValueAtTime(0, start);
      gain.gain.linearRampToValueAtTime(.09, start + .025);
      gain.gain.exponentialRampToValueAtTime(.001, start + .38);
      tone.connect(gain); gain.connect(audio.destination);
      tone.start(start); tone.stop(start + .4);
    });
    setTimeout(() => audio.close().catch(() => {}), 1200);
  } catch (_) { /* Sound support never blocks completion. */ }
}

function celebratePractice(problem) {
  playCompletionFanfare();
  clearTimeout(celebrationTimer);
  const allDone = problem !== "P00" && completedPractices.size === 23;
  setText("completion-problem", allDone ? "23 / 23" : missionLabel(problem));
  setText("completion-title", problem === "P00" ? "첫 미션 클리어! 🎉" : allDone ? "23개 문제, 모두 해냈습니다." : `${missionLabel(problem)} 미션 클리어! 🎉`);
  setText("completion-message", problem === "P00" ? "직접 만든 요청이 서버에 정확히 도착했습니다. 다음 미션도 가보죠!" : allDone ? "모든 문제의 완료를 확인했습니다. 수고하셨습니다!"
    : `직접 작성한 구현이 검증을 통과했습니다. ${completedPractices.size}개 완료!`);
  byId("completion-toast").hidden = false;
  if (!window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
    const overlay = byId("completion-confetti");
    overlay.hidden = false;
    const burst = document.createElement("div"); burst.className = "completion-burst";
    overlay.append(burst);
    for (let index = 0; index < 160; index++) {
      const piece = document.createElement("i");
      piece.style.setProperty("--x", `${Math.random() * 100}%`);
      piece.style.setProperty("--delay", `${Math.random() * .7}s`);
      piece.style.setProperty("--duration", `${2.2 + Math.random() * 1.4}s`);
      piece.style.setProperty("--drift", `${(Math.random() - .5) * 24}vw`);
      piece.style.setProperty("--rotation", `${360 + Math.random() * 720}deg`);
      burst.append(piece);
    }
    setTimeout(() => { burst.remove(); if (!overlay.childElementCount) overlay.hidden = true; }, 4500);
  } else {
    byId("completion-confetti").replaceChildren();
    byId("completion-confetti").hidden = true;
  }
  celebrationTimer = setTimeout(dismissCelebration, 6500);
}

function recordPracticeCompletion(payload, problem) {
  if (!practiceGroups.some(group => group.includes(problem))) return;
  const summary = verificationSummary(payload);
  if (!payload.client_error && summary?.problem === problem && summary.completed === "완료") {
    completedPractices.set(problem, summary.execution);
    recheckPractices.delete(problem);
    renderPracticeProgress();
    celebratePractice(problem);
  } else {
    completedPractices.delete(problem);
    renderPracticeProgress();
  }
}

function renderSidebarPin() {
  byId("mission-menu-toggle").setAttribute("aria-pressed", String(sidebarPinned));

}
function setSidebarPinned(pinned) {
  sidebarPinned = pinned;
  try { localStorage.setItem("guided-sidebar-pinned", String(pinned)); } catch {}
  renderSidebarPin();
}
function handleMissionMenuKey(event) {
  const items = [...byId("tabs").querySelectorAll(".tab")].filter(item => item.getClientRects().length);
  const index = items.indexOf(event.currentTarget);
  const steps = {ArrowRight: 1, ArrowDown: 1, ArrowLeft: -1, ArrowUp: -1};
  const next = event.key === "Home" ? 0 : event.key === "End" ? items.length - 1
    : event.key in steps ? (index + steps[event.key] + items.length) % items.length : null;
  if (next === null) return;
  event.preventDefault();
  if (items[next].id === "p00-menu") selectWorkspace("tutorial");
  else selectTab(Number(items[next].dataset.tabIndex), items[next].dataset.problem);
  setMissionMenu(true); items[next].focus();
}

function setMissionMenu(open) {
  const wasOpen = !byId("mission-menu").hidden;
  byId("mission-menu").hidden = !open;
  byId("workspace-shell").classList.toggle("menu-open", open);
  byId("mission-menu-backdrop").hidden = !open || !window.matchMedia("(max-width: 760px)").matches;
  byId("mission-menu-toggle").setAttribute("aria-expanded", String(open));
  byId("mission-menu-chevron").setAttribute("d", open ? "m15 6-6 6 6 6" : "m9 6 6 6-6 6");
  byId("mission-menu-toggle").setAttribute("aria-label", open ? "사이드 메뉴 닫기" : "사이드 메뉴 열고 고정하기");
  if (open && !wasOpen) {
    const selected = byId("mission-menu").querySelector('.tab[aria-selected="true"]') || byId("p00-menu");
    selected.focus({preventScroll: true});
  }
}

function selectWorkspace(name) {
  byId("home-masthead").hidden = name !== "home";
  byId("resource-operation").hidden = true;
  for (const item of ["home", "missions"]) {
    const selected = item === (name === "tutorial" ? "missions" : name);
    byId(`workspace-${item}`).setAttribute("aria-selected", String(selected));
    byId(`workspace-${item}`).tabIndex = selected ? 0 : -1;
  }
  byId("tutorial-panel").hidden = name !== "tutorial";
  byId("mission-panel").hidden = name !== "missions";
  byId("home-panel").hidden = name !== "home";
  byId("p00-menu").removeAttribute("aria-current");
  document.querySelectorAll(".tab").forEach(tab => {
    const selected = name === "tutorial" && tab.id === "p00-menu";
    tab.classList.toggle("active", selected);
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
  });
  if (name === "home") {
    renderHomeProgress();
    renderBreadcrumb(null);
    setText("current-station-name", "완료한 미션");
  }
  setMissionMenu(sidebarPinned && window.matchMedia("(min-width: 761px)").matches);
  if (name === "tutorial") {
    window.scrollTo({top: 0, left: 0, behavior: "instant"});
    byId("tutorial-panel").scrollTop = 0;
    selectTutorialPane("experience");
    byId("p00-menu").setAttribute("aria-current", "page");
    renderBreadcrumb("P00");
    setText("current-station", "P00");
    setText("current-station-name", "첫 미션 튜토리얼");
    showAdminAnswer("P00");
  }
}

function appendAdminInline(parent, text) {
  const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g);
  for (const part of parts) {
    if (part.startsWith("`") && part.endsWith("`")) {
      const code = document.createElement("code");
      code.textContent = part.slice(1, -1);
      parent.append(code);
    } else if (part.startsWith("**") && part.endsWith("**")) {
      const strong = document.createElement("strong");
      strong.textContent = part.slice(2, -2);
      parent.append(strong);
    } else {
      parent.append(document.createTextNode(part));
    }
  }
}

function renderAdminMarkdown(container, source) {
  container.replaceChildren();
  const lines = String(source || "").replace(/\r\n?/g, "\n").split("\n");
  let index = 0;
  while (index < lines.length) {
    const line = lines[index];
    if (!line.trim()) { index += 1; continue; }
    const fence = line.match(/^```([\w+-]*)\s*$/);
    if (fence) {
      const codeLines = [];
      index += 1;
      while (index < lines.length && !lines[index].startsWith("```")) codeLines.push(lines[index++]);
      if (index < lines.length) index += 1;
      const pre = document.createElement("pre");
      const code = document.createElement("code");
      if (fence[1]) code.className = `language-${fence[1]}`;
      code.textContent = codeLines.join("\n");
      pre.append(code); container.append(pre); continue;
    }
    const heading = line.match(/^(#{1,4})\s+(.+)$/);
    if (heading) {
      const level = Math.min(heading[1].length + 1, 4);
      const node = document.createElement(`h${level}`);
      appendAdminInline(node, heading[2]);
      container.append(node); index += 1; continue;
    }
    const bullet = line.match(/^[-*]\s+(.+)$/);
    const numbered = line.match(/^\d+\.\s+(.+)$/);
    if (bullet || numbered) {
      const list = document.createElement(numbered ? "ol" : "ul");
      const pattern = numbered ? /^\d+\.\s+(.+)$/ : /^[-*]\s+(.+)$/;
      while (index < lines.length) {
        const item = lines[index].match(pattern);
        if (!item) break;
        const li = document.createElement("li"); appendAdminInline(li, item[1]); list.append(li); index += 1;
      }
      container.append(list); continue;
    }
    const paragraphLines = [line.trim()];
    index += 1;
    while (index < lines.length && lines[index].trim() && !/^(#{1,4})\s+|^```|^[-*]\s+|^\d+\.\s+/.test(lines[index])) {
      paragraphLines.push(lines[index].trim()); index += 1;
    }
    const paragraph = document.createElement("p");
    appendAdminInline(paragraph, paragraphLines.join(" "));
    container.append(paragraph);
  }
}

function prepareAdminAnswerMarkdown(source) {
  const lines = String(source || "").replace(/\r\n?/g, "\n").split("\n");
  const visible = [];
  let excluded = false;
  for (const line of lines) {
    if (/^#\s+/.test(line)) continue;
    const section = line.match(/^##\s+(.+)$/);
    if (section) {
      excluded = /^(판정|누락|남은 누락|최종 결론)/.test(section[1]);
      if (excluded) continue;
      const label = /^(완성 답( 전체)?|전체 완성 답|정확한 제출 답)$/.test(section[1])
        ? "정답 코드"
        : /^(조건 충족 확인|요구사항과의 대응|채점 조건과의 대응|답의 근거|구현이 충족하는 조건)$/.test(section[1])
          ? "코드 설명"
          : section[1];
      visible.push(`## ${label}`); continue;
    }
    if (!excluded) visible.push(line);
  }
  return visible.join("\n").trim();
}

async function writeClipboard(text) {
  let fallbackField = null;
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
    } else {
      fallbackField = document.createElement("textarea");
      fallbackField.value = text; fallbackField.setAttribute("readonly", "");
      fallbackField.className = "clipboard-fallback"; document.body.append(fallbackField);
      fallbackField.select();
      if (!document.execCommand("copy")) throw new Error("copy failed");
    }
    return true;
  } catch {
    return false;
  } finally {
    fallbackField?.remove();
  }
}

function prepareCopyableBlocks(root = document) {
  for (const pre of root.querySelectorAll("pre:not([id])")) {
    if (pre.parentElement?.classList.contains("copyable-block")) continue;
    const wrapper = document.createElement("div"); wrapper.className = "copyable-block";
    const button = document.createElement("button");
    button.type = "button"; button.className = "secondary copy-block-button";
    button.textContent = "복사"; button.setAttribute("aria-label", "이 블록 복사");
    button.addEventListener("click", async () => {
      const copied = await writeClipboard(pre.textContent);
      button.textContent = copied ? "복사됨" : "복사 실패";
      window.setTimeout(() => { button.textContent = "복사"; }, 1600);
    });
    pre.replaceWith(wrapper); wrapper.append(pre, button);
  }
}

async function showAdminAnswer(problem) {
  if (!adminMode || !adminAnswerPanel) return;
  const requestNumber = ++adminAnswerRequest;
  const host = problem === "P00" ? byId("tutorial-panel") : byId(`h${problem.slice(1)}-work`);
  host.append(adminAnswerPanel);
  adminAnswerPanel.open = false;
  const output = adminAnswerPanel.querySelector(".admin-answer-content");
  output.textContent = "관리자 답안을 불러오는 중입니다…";
  try {
    const response = await fetch(`/api/admin/answers/${problem}`);
    const payload = await response.json();
    if (!response.ok) throw new Error(payload.detail || "관리자 답안을 불러오지 못했습니다.");
    if (requestNumber === adminAnswerRequest) {
      renderAdminMarkdown(output, prepareAdminAnswerMarkdown(payload.answer));
      prepareCopyableBlocks(output);
    }
  } catch (error) {
    if (requestNumber === adminAnswerRequest) output.textContent = error.message;
  }
}

function prepareAdminAnswers() {
  if (!adminMode) return;
  adminAnswerPanel = document.createElement("details");
  adminAnswerPanel.className = "admin-answer";
  const title = document.createElement("summary"); title.textContent = "관리자 답안";
  const note = document.createElement("p");
  note.textContent = "현재 문제의 제한된 조건과 Starter만 사용한 독립 풀이입니다.";
  const output = document.createElement("div"); output.className = "admin-answer-content";
  adminAnswerPanel.append(title, note, output);
}

function prepareMissionPanes() {
  const body = byId("practice-workbench").querySelector(".work-body");
  const guidance = document.createElement("div"); guidance.id = "mission-guidance";
  const execution = document.createElement("section"); execution.id = "mission-execution";
  const title = document.createElement("h3"); title.textContent = "문제 해결";
  const actions = document.createElement("div"); actions.id = "mission-execution-actions";
  execution.append(title, byId("h23-experience-tabs"), byId("h23-experience"), byId("mission-experience"), byId("resource-operation"), actions);
  body.append(guidance, execution);
  const gateway = byId("h01-work");
  const context = gateway.querySelector(".mission-context");
  gateway.querySelector(".p01-statement").prepend(context);
  const gatewayExecution = gateway.querySelector(".p01-execution");
  gatewayExecution.id = "gateway-execution";
  execution.append(gatewayExecution);
  guidance.append(gateway);

  const resourceActions = document.createElement("div"); resourceActions.id = "mission-resource-actions";
  byId("mission-experience").prepend(resourceActions, byId("resource-operation"));
  for (const node of [...body.children]) {
    if (node.classList.contains("lab-workspace") && node.id !== "h01-work") guidance.append(node);
  }
  for (const number of ["03", "06"]) {
    const nested = byId(`h${number}-work`);
    nested.classList.remove("hands-on"); nested.classList.add("lab-workspace");
    guidance.append(nested);
  }
  for (const node of guidance.querySelectorAll(".actions")) {
    const button = node.querySelector('button[id^="h"]');
    const number = button?.id.match(/^h(\d{2})-/)?.[1];
    if (!number) continue;
    const group = document.createElement("section"); group.dataset.problem = `P${number}`;
    const heading = document.createElement("h4"); heading.textContent = `${missionLabel(`P${number}`)} · 실행`;
    const resourceGroup = document.createElement("section"); resourceGroup.dataset.problem = `P${number}`;
    const resourceControls = document.createElement("div"); resourceControls.className = "actions";
    for (const control of [...node.querySelectorAll(".action-control")]) {
      if (control.querySelector('button[id$="-provision"], button[id$="-delete"]')) resourceControls.append(control);
    }
    if (resourceControls.children.length) {
      const resourceHeading = document.createElement("h4"); resourceHeading.textContent = "AWS 자원 관리";
      resourceGroup.append(resourceHeading, resourceControls); resourceActions.append(resourceGroup);
      const statusButton = document.createElement("button"); statusButton.type = "button";
      statusButton.textContent = "AWS 자원 상태 확인";
      statusButton.dataset.resourceStatus = `P${number}`;
      const statusOutput = document.createElement("div"); statusOutput.setAttribute("aria-live", "polite");
      const statusHelp = document.createElement("p"); statusHelp.className = "action-tooltip";
      statusHelp.textContent = "AWS 자원이 준비되어 있는지와 현재 서비스 상태를 조회합니다. 정책 검증·문서 동기화·미션 채점은 별도로 실행하세요.";
      resourceControls.append(statusButton); resourceGroup.append(statusHelp, statusOutput);
      resourceControls.className = "aws-resource-toolbar";
      resourceControls.setAttribute("role", "group"); resourceControls.setAttribute("aria-label", "AWS 자원 관리");
      const icons = {
        status: '<circle cx="10" cy="10" r="7"/><path d="m15 15 6 6M7 10l2 2 4-4"/>',
        prepare: '<path d="M7 17H5a4 4 0 0 1-.5-8 7 7 0 0 1 13-1 4.5 4.5 0 0 1 1.5 9h-2M12 19V10m-3 3 3-3 3 3"/>',
        delete: '<path d="M4 6h16M9 6V3h6v3M6 6l1 15h10l1-15M10 10v7m4-7v7"/>'
      };
      const preparation = resourceControls.querySelector('button[id$="-provision"]');
      const deletion = resourceControls.querySelector('button[id$="-delete"]');
      const help = document.createElement("details"); help.className = "aws-resource-help";
      const helpTitle = document.createElement("summary"); helpTitle.textContent = "자원 작업 안내"; help.append(helpTitle);
      for (const note of resourceControls.querySelectorAll(".action-tooltip")) help.append(note);
      for (const control of [...resourceControls.children]) if (control !== statusButton) control.remove();
      for (const [button, kind, label] of [[statusButton,"status","AWS 자원 상태 확인"], [preparation,"prepare","AWS 자원 준비"], [deletion,"delete","AWS 자원 삭제"]]) {
        button.className = `aws-resource-icon aws-resource-${kind}`;
        button.setAttribute("aria-label", label); button.title = label;
        const svg = document.createElementNS("http://www.w3.org/2000/svg", "svg");
        for (const [key, value] of Object.entries({viewBox:"0 0 24 24", fill:"none", stroke:"currentColor", "stroke-width":"1.7", "stroke-linecap":"round", "stroke-linejoin":"round", "aria-hidden":"true"})) svg.setAttribute(key, value);
        const shapes = new DOMParser().parseFromString(`<svg xmlns="http://www.w3.org/2000/svg">${icons[kind]}</svg>`, "image/svg+xml");
        for (const shape of [...shapes.documentElement.children]) svg.append(document.importNode(shape, true));
        button.replaceChildren(svg);
        resourceControls.append(button);
      }
      resourceControls.after(statusOutput); resourceGroup.append(help);

      statusButton.addEventListener("click", async () => {
        if (number === "03") updateKnowledgeLinks({resources: []});
        if (number === "04") updateGuardrailChat({});
        statusButton.disabled = true; statusOutput.classList.remove("aws-status-problem"); statusOutput.textContent = "AWS 자원과 저장·연결·동기화 정보를 확인하고 있습니다…";
        const checking = document.createElement("progress"); checking.setAttribute("aria-label", "AWS 자원 상태 확인 중");
        statusOutput.prepend(checking);
        try {
          const response = await fetch(`/api/resource-status/P${number}`);
          const payload = await response.json();
          if (!response.ok) throw new Error(payload.detail || "AWS 상태 조회 실패");
          if (number === "02") updateDocumentLinks(payload);
          if (number === "03") updateKnowledgeLinks(payload);
          if (number === "04") updateGuardrailChat(payload);
          const labels = {present: "확인됨", absent: "미생성", partial: "일부 자원 준비 필요", unknown: "상태 조회 실패", unavailable: "AWS 조회 불가"};
          statusOutput.replaceChildren();
          const statusDetails = document.createElement("details"); statusDetails.className = "aws-status-details";
          const statusSummary = document.createElement("summary");
          const hasProblem = resource => resource.state !== "present" || resource.inspection_error || ["FAILED", "DELETING", "DELETE_UNSUCCESSFUL"].includes(resource.aws_status) || resource.facts?.["최근 동기화"] === "FAILED";
          const problemFound = payload.state !== "present" || payload.search_ready === false || (payload.resources || []).some(hasProblem);
          statusSummary.className = problemFound ? "aws-status-problem" : "aws-status-healthy";
          statusSummary.textContent = `${missionLabel(`P${number}`)} · ${payload.state === "present" ? (problemFound ? "상세 상태 확인 필요" : "AWS 자원 확인 완료") : labels[payload.state] || payload.state} · 확인 시각: ${new Date(payload.checked_at).toLocaleString("ko-KR")}`;
          statusDetails.append(statusSummary);
          if (payload.search_detail) { const readiness = document.createElement("p"); readiness.textContent = payload.search_detail; statusDetails.append(readiness); }
          if (payload.detail) { const detail = document.createElement("p"); detail.textContent = payload.detail; statusDetails.append(detail); }
          const list = document.createElement("ul"); list.className = "aws-resource-list";
          const names = {"S3 source bucket":"문서 원본 저장소", "S3 vector bucket":"검색 벡터 저장소", "Vector index":"벡터 검색 인덱스", "IAM role":"Knowledge Base 실행 권한", "Knowledge Base":"Knowledge Base", "Data source":"문서 연결·동기화", "AWS Guardrail":"AWS Guardrail"};
          for (const resource of payload.resources || []) {
            const row = document.createElement("li"); row.className = "aws-resource-row";
            const heading = document.createElement("strong"); heading.className = hasProblem(resource) ? "aws-status-problem" : "aws-status-healthy"; heading.textContent = `${names[resource.type] || resource.type}: ${labels[resource.state]}${resource.aws_status ? ` · ${resource.aws_status}` : ""}`;
            const identity = document.createElement("code"); identity.textContent = resource.name;
            row.append(heading, identity);
            const facts = document.createElement("dl");
            for (const [key, value] of Object.entries(resource.facts || {})) {
              if (value == null || value === "") continue;
              const term = document.createElement("dt"); term.textContent = key;
              const description = document.createElement("dd"); description.textContent = String(value);
              facts.append(term, description);
            }
            row.append(facts);
            if (resource.detail || resource.inspection_error) {
              const error = document.createElement("p"); error.textContent = resource.detail || resource.inspection_error; row.append(error);
            }
            if (resource.state === "present" && resource.console_url?.startsWith("https://us-east-1.console.aws.amazon.com/")) {
              const link = document.createElement("a"); link.href = resource.console_url; link.target = "_blank"; link.rel = "noopener noreferrer"; link.textContent = "AWS에서 확인 ↗"; row.append(link);
              if (resource.console_hint) { const hint = document.createElement("p"); hint.textContent = resource.console_hint; row.append(hint); }
            }
            list.append(row);
          }
          const raw = document.createElement("details"); const summary = document.createElement("summary");
          summary.textContent = "RAW 응답 전체"; const pre = document.createElement("pre"); pre.textContent = JSON.stringify(payload, null, 2);
          raw.append(summary, pre); statusDetails.append(list, raw); statusOutput.append(statusDetails);
        } catch (error) { statusOutput.textContent = error.message; statusOutput.classList.add("aws-status-problem"); }
        finally { statusButton.disabled = false; }
      });

    }
    group.append(heading, node); actions.append(group);
  }
}

let p01ResultHomes = [];
function arrangeP01Results(active) {
  if (!p01ResultHomes.length) {
    const nodes = [byId("grading-checked-at"), byId("case-results"), byId("case-progress"), document.querySelector(".inspection"), byId("failure-help"), byId("raw").closest("details"), document.querySelector(".receipt")];
    p01ResultHomes = nodes.map(node => {
      const home = document.createComment("result home");
      node.before(home);
      return {node, home};
    });
  }
  for (const {node, home} of p01ResultHomes) {
    if (active) byId("p01-results").append(node);
    else byId("mission-execution").append(node);
  }
  byId("mission-panel").classList.remove("p01-layout");
  byId("mission-panel").classList.add("general-mission-layout");
  byId("mission-guidance").hidden = false;
  byId("mission-execution").hidden = false;
  byId("gateway-execution").hidden = !active;
}

function selectTab(index, problem = practiceGroups[index][0]) {
  selectWorkspace("missions");
  byId("p00-menu").removeAttribute("aria-current");
  arrangeP01Results(index === 0);
  dismissCelebration();
  activeTab = index;
  activeProblem = problem;
  byId("h23-experience-tabs").hidden = problem === "P01";
  byId("h23-experience").hidden = true;
  byId("mission-experience").hidden = true;
  setText("mission-experience-status", "실행하면 현재 기능의 응답을 확인할 수 있습니다.");
  byId("mission-experience-details").hidden = true;
  byId("mission-experience-summary").replaceChildren();
  byId("resource-raw-details").hidden = true;
  selectModelCallPane("grade", false);
  const selectedCategory = document.querySelector(`.tab[data-problem="${problem}"]`).closest(".mission-category");
  document.querySelectorAll(".mission-category").forEach(section => section.classList.toggle("is-current", section === selectedCategory));
  for (const group of byId("mission-execution-actions").children) group.hidden = group.dataset.problem !== problem;
  document.querySelectorAll(".tab").forEach((tab) => {
    const selected = tab.dataset.problem === problem;
    tab.classList.toggle("active", selected);
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
  });
  byId("practice-workbench").setAttribute("aria-labelledby", document.querySelector(`.tab[data-problem="${problem}"]`).id);
  byId("failure-help").hidden = true;
  for (let number = 1; number <= 23; number++) {
    byId(`h${String(number).padStart(2, "0")}-work`).hidden = problem !== `P${String(number).padStart(2, "0")}`;
  }
  window.scrollTo({top: 0, left: 0, behavior: "instant"});
  byId("mission-guidance").scrollTop = 0;
  byId("mission-execution").scrollTop = 0;
  showAdminAnswer(problem);
  const h09 = index === 5;
  const h22 = index === 12;
  setText("current-station", missionLabel(activeProblem));
  const activityIds=["P01","P23·P02·P03","P04","P05·P06","P07·P08","P09·P10","P11·P12","P13","P14·P15","P16","P17·P18","P19·P20","P21·P22"];
  byId("task-completion").hidden = true;
  byId("task-completion").textContent = "";
  const stationNames=["Nova Lite 요청 경로","Embedding·Knowledge Base","Bedrock 관리형 Guardrail","NeMo Dialog Rail·Action","NeMo 입력 안전","Presidio·출력 Rail","RAG 인증·출처 경계","Promptfoo 회귀 Test","Garak·PyRIT 탐색","정책 승격","원시 관측","사고·경보","Agent·MCP 실행 경계"];
  const activityTitles=["AI 호출 게이트를 지켜라!","원문 저장과 현재 검색 연결하기","관리형 Guardrail을 Nova Lite에 연결하기","한국어 Dialog Rail과 Python Action 만들기","위험 입력을 Main Model 전에 멈추기","개인정보와 위험한 출력이 밖으로 나가기 전에 멈추기","RAG 권한과 Application 단일 진입점 만들기","Promptfoo 회귀 Test 작성하기","Red Team 후보를 실제 영향으로 재확인하기","검증된 정책만 승격하기","Log·Trace·Metric 원시 신호 연결하기","사고 조사와 경보 수명주기 확인하기","Agent 실행 정책과 MCP 승인 만들기"];
  renderBreadcrumb(activeProblem);
  setText("current-station-name",stationNames[index]); setText("activity-label",`PRACTICE · ${missionLabel(activeProblem)}`); setText("activity-title", homeMissions.find(item => item.id === activeProblem).title);
  setText("provider-label", h09 ? "SOURCE" : index === 0 ? "PROVIDER" : index === 1 ? "TITAN REQUEST" : index === 2 ? "AWS REQUEST" : index === 3 ? "EVALUATION" : "TOOL CATALOG");
  setText("model-label", h09 ? "FRAMEWORK" : index === 0 ? "MODEL" : index === 1 ? "EMBED MODEL" : index === 2 ? "GUARDRAIL" : index === 3 ? "FRAMEWORK" : "PROTOCOL");
  setText("requested-label", h09 ? "ENTITIES" : h22 ? "EFFECT ORDER" : index === 0 ? "REQUESTED" : index === 1 ? "OBJECT KEY" : index === 3 ? "SAMPLES" : "ACTION");
  setText("effective-label", h09 ? "DELIVERIES" : h22 ? "SERVER" : index === 0 ? "EFFECTIVE" : index === 1 ? "DIMENSION" : index === 3 ? "EVAL ERRORS" : "STOP REASON");
  setText("output-label", h09 ? "RAW RISK" : h22 ? "EFFECTS" : index === 0 ? "OUTPUT TOKENS" : index === 1 ? "DATA SOURCE" : index === 3 ? "RISK BOT MESSAGE" : "OUTPUT");
  if (problem === "P23") {
    setText("provider-label", "AWS REQUEST"); setText("model-label", "MODEL");
    setText("requested-label", "REQUESTED"); setText("effective-label", "FORWARDED");
    setText("output-label", "OUTPUT TOKENS");
  }
  byId("case-progress").hidden = true;
  byId("resource-operation").hidden = true;
  const previous = missionResults.get(problem);
  if (previous) {
    showMissionResults();
    renderEnvelope(previous);
    setText("request-status", "이 미션의 최근 실행 결과입니다.");
  } else {
    for (const {node} of p01ResultHomes) node.hidden = true;
    byId("case-results").hidden = true;
    setText("request-status", "검증을 시작하면 이곳에서 요청 상태를 확인할 수 있습니다.");
  }
  if (problem === "P01") selectP01Pane("model");
  else selectModelCallPane("experience", false);
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
    if (item.id === "grafana" || item.id === "p20-grafana") {
      const card = document.createElement("div");
      card.className = "official-card";
      const help = document.createElement("details");
      help.className = "login-help";
      const summary = document.createElement("summary");
      summary.textContent = "로그인 방법";
      const user = document.createElement("p");
      const p20 = item.id === "p20-grafana";
      user.textContent = `아이디: ${p20 ? "p20-reader (조회 전용)" : "admin"}. 실행에 사용한 setup 폴더에서 아래 명령으로 비밀번호를 확인하세요.`;
      const command = document.createElement("pre");
      command.textContent = `grep '^${p20 ? "GUIDED_P20_GRAFANA_PASSWORD" : "GUIDED_GRAFANA_PASSWORD"}=' llm-security-control-plane/.state/guided-course.env`;
      const note = document.createElement("p");
      note.textContent = "출력의 = 뒤가 비밀번호입니다. 환경 파일을 다시 만들지 말고 기존 값을 사용하세요. 비밀번호는 이 화면으로 전송하지 않습니다.";
      help.append(summary, user, command, note);
      card.append(link, help);
      nav.append(card);
    } else nav.append(link);
  });
}

let sessionRefreshPromise = null;
let sessionCheckedAt = 0;

async function refreshBrowserSession(beforeRequest = false) {
  if (!csrfToken || (executionPending && !beforeRequest)) return;
  if (sessionRefreshPromise) return sessionRefreshPromise;
  if (Date.now() - sessionCheckedAt < 60000) return;
  sessionRefreshPromise = (async () => {
    let response = await fetch("/api/session/refresh", {method: "POST", headers: {"X-CSRF-Token": csrfToken}});
    if (response.status === 401 || response.status === 403) {
      // Reconnect only the browser session; never replay a grading or AWS request.
      const home = await fetch("/", {cache: "no-store"});
      if (!home.ok) throw new Error("실습실 세션에 다시 연결하지 못했습니다.");
      const bootstrapResponse = await fetch("/api/bootstrap", {cache: "no-store"});
      if (!bootstrapResponse.ok) throw new Error("실습실 세션을 갱신하지 못했습니다.");
      const payload = await bootstrapResponse.json();
      csrfToken = payload.csrf_token;
      setText("tutorial-submit-command", `curl -sS -X POST '${location.origin}/api/practice/P00/check' \\
  -H 'Authorization: Bearer ${payload.p00_submission_token}' \\
  -H 'Content-Type: application/json' \\
  --data-binary @"$HOME/work/control-center-tutorial/request.json" | jq`);
      response = await fetch("/api/session/refresh", {method: "POST", headers: {"X-CSRF-Token": csrfToken}});
    }
    if (!response.ok) throw new Error("실습실 세션을 갱신하지 못했습니다.");
    sessionCheckedAt = Date.now();
  })();
  try { await sessionRefreshPromise; } finally { sessionRefreshPromise = null; }
}

setInterval(() => {
  if (!document.hidden) refreshBrowserSession().catch(() => {});
}, 60000);
document.addEventListener("visibilitychange", () => {
  if (!document.hidden) refreshBrowserSession().catch(() => {});
});

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
  await refreshBrowserSession(true);
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
    const diagnostic = payload.diagnosis;
    const original = typeof payload.detail === "string" ? payload.detail : JSON.stringify(payload.detail);
    error.detail = diagnostic ? [original, diagnostic.cause, `수정 파일: ${diagnostic.file}`, diagnostic.field ? `확인 항목: ${diagnostic.field}` : "", `모델 호출: ${diagnostic.model_calls}`, `다음 행동: ${diagnostic.next_action}`, diagnostic.log_command ? `실행 로그 확인:\n${diagnostic.log_command}` : ""].filter(Boolean).join("\n") : payload.detail;
    error.httpStatus = response.status;
    throw error;
  }
  return payload;
}

function setBusy(busy, showExecution = true) {
  executionPending = busy;
  byId("practice-workbench").setAttribute("aria-busy", String(busy));
  document.querySelectorAll(".tab").forEach(tab => { tab.disabled = busy; });
  ["navigation-home", "breadcrumb-home", "breadcrumb-category", "preflight", "verify", "chat-send", "h02-provision", "h02-delete", "h02-verify", "h03-provision", "h03-delete", "h03-verify", "h04-provision", "h04-delete", "h04-verify", "h05-verify", "h06-verify", "h07-verify", "h08-verify", "h09-verify", "h10-verify", "h11-verify", "h12-verify", "h13-verify", "h14-verify", "h15-verify", "h16-verify", "h17-verify", "h18-verify", "h19-verify", "h20-verify", "h21-verify", "h22-verify", "h23-verify", "h23-chat-send", "h23-experience-tab", "h23-grade-tab", "mission-experience-run"].forEach((id) => {
    if (byId(id)) byId(id).disabled = busy;
  });
  const searchButton = byId("knowledge-search-submit");
  searchButton.disabled = busy || searchButton.dataset.resourceReady !== "true";
  const guardrailButton = byId("guardrail-chat-submit");
  guardrailButton.disabled = busy || guardrailButton.dataset.resourceReady !== "true";
  if (busy && showExecution) {
    setText("execution-state", "응답 대기 · 실제 실행 단계는 아직 미확인");
    document.querySelectorAll(".gate").forEach((gate) => {
      gate.className = "gate";
      gate.querySelector("small").textContent = "미확인";
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
  if (executionPending) return;
  const prompt = byId("chat-input").value.trim();
  if (!prompt) return;
  appendChatMessage("user", prompt);
  setBusy(true, false);
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
    setBusy(false, false);
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

function showMissionResults() {
  for (const node of [document.querySelector(".inspection"), document.querySelector(".receipt"), byId("raw").closest("details")]) node.hidden = false;
}

function renderResourceProgress(progress) {
  if (!progress || !Number.isInteger(progress.current) || !Number.isInteger(progress.total)
      || progress.total < 1 || progress.current < 0 || progress.current > progress.total) return;
  const bar = byId("resource-operation-bar");
  bar.max = progress.total;
  bar.value = progress.current;
  setText("resource-operation-count", `${progress.current} / ${progress.total}`);
  setText("resource-operation-label", progress.title);
  setText("resource-operation-detail", progress.description);
}

function renderEnvelope(payload) {
  showMissionResults();
  renderReportedCases(payload);
  setText("raw", rawResponses.get(payload) ?? JSON.stringify(payload, null, 2));
  if (payload.resource_ready === true || payload.resource_deleted === true) {
    if (payload.activity_id === "P02") {
      const resources = payload.preparation?.resources;
      updateDocumentLinks(payload.resource_deleted ? {state:"absent",resources:[]} : {state:"present",resources:resources?.provider_mode === "aws" ? [{type:"S3 source bucket",name:resources.source_bucket,state:"present"}] : [], prepared: resources?.provider_mode === "aws"});
    }
    if (payload.activity_id === "P04") {
      updateGuardrailChat({});
      if (payload.resource_ready) document.querySelector('[data-resource-status="P04"]')?.click?.();
    }
    if (payload.activity_id === "P03") {
      updateKnowledgeLinks({resources: []});
      if (payload.resource_ready) document.querySelector('[data-resource-status="P03"]')?.click?.();
    }
    byId("resource-operation").hidden = false;
    renderResourceProgress(payload.resource_progress);
    setText("resource-operation-label", payload.resource_deleted ? "AWS 자원 삭제 완료" : "AWS 자원 준비 완료");
    setText("resource-operation-detail", "미션은 아직 채점하지 않았습니다. " + (payload.next_check || "코드를 적용한 뒤 미션 채점을 실행하세요."));
    document.querySelector(".inspection").hidden = true;
    document.querySelector(".receipt").hidden = true;
    byId("case-results").hidden = true;
    for (const {node} of p01ResultHomes) node.hidden = true;
    setText("resource-raw", rawResponses.get(payload) ?? JSON.stringify(payload, null, 2));
    byId("resource-raw-details").hidden = false;
    setText("execution-state", payload.resource_deleted ? "자원 삭제 완료 · 미채점" : "자원 준비 완료 · 미채점");
    return;
  }
  setText("grading-checked-at", gradingTimeLabel(payload));
  byId("grading-checked-at").hidden = false;
  if (payload.activity_id === "P23") document.querySelector(".inspection").hidden = true;
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
  setText("next-check", `다음 확인: ${payload.next_check || "RAW 응답에서 실패한 단계와 현재 실행 ID를 확인합니다."}`);
  setText("execution-state", payload.execution_id || "실행 실패");

  const verdict = byId("verdict");
  const taskCompletion = byId("task-completion");
  taskCompletion.hidden = typeof payload.task_completed !== "boolean";
  taskCompletion.textContent = taskCompletion.hidden ? "" : `${payload.activity_id} 과제: ${payload.task_completed ? "완료" : "미완료"}`;
  verdict.className = `verdict ${(payload.course_verdict || "ERR").toLowerCase()}`;
  verdict.querySelector("strong").textContent = payload.course_verdict || "ERR";
  verdict.querySelector("span").textContent = payload.verified_by || "검증 실패";

  const stages = [{ stage: "control_center", outcome: payload.client_error ? "응답 확인 실패" : "completed" }, ...(payload.stage_calls || [])];
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

function verificationSummary(payload) {
  if (!/^P\d{2}$/.test(payload.activity_id || "") || !payload.execution_id || !payload.verified_by
      || payload.resource_ready || typeof payload.task_completed !== "boolean"
      || !["HIT", "PASS", "ERR"].includes(payload.course_verdict)) return null;
  const value = payload.source_digest || payload.result?.source_digest || payload.result?.receipt?.source_digest;
  return {problem: payload.activity_id, execution: payload.execution_id,
    digest: typeof value === "string" && /^[a-f0-9]{64}$/.test(value) ? value : "미확인",
    completed: payload.task_completed && payload.course_verdict !== "ERR" ? "완료" : "미완료",
    verdict: payload.course_verdict, stage: payload.stage_calls?.at(-1)?.stage || "미확인"};
}

function failureCategory(payload) {
  const labels = {input: "입력", implementation: "구현", environment: "환경", evidence: "증거"};
  if (Object.hasOwn(labels, payload.failure_category)) return labels[payload.failure_category];
  if (payload.http_status === 422) return "입력";
  if (payload.http_status === 501) return "구현";
  if (["credentials_missing", "credentials_invalid", "access_denied", "model_unavailable", "provider_error"].includes(payload.provider_error)) return "환경";
  return "미분류 — 응답만으로 원인을 확정하지 못했습니다";
}

function renderLearningSupport(payload, problem) {
  byId("failure-help").hidden = payload.course_verdict !== "ERR";
  setText("failure-category", `확인할 범위: ${failureCategory(payload)}. 아래에서 해당 항목을 확인하세요.`);
}

function renderError(error) {
  const payload = { course_verdict: "ERR", client_error: true,
    reason: "검증 응답을 확인하지 못했습니다. 뒤 서비스의 실행 여부는 아직 알 수 없습니다.",
    next_check: "원시 오류를 먼저 확인합니다. 연결 오류라면 해당 문제의 컨테이너 상태를 확인합니다.",
    error: error.message, stage_calls: [] };
  if (/^P\d{2}$/.test(error.detail?.activity_id || "") && error.detail.task_completed === false) {
    Object.assign(payload, error.detail, { course_verdict: "ERR", security_verdict: "ERR", task_completed: false, client_error: true });
  }
  renderEnvelope(payload);
}

function displayCaseValue(value) {
  const serialized = JSON.stringify(value, (key, item) => {
    if (gradingCredentialKey(key) || /_(token|secret|password|capability)$/i.test(key)) return "[비공개]";
    return typeof item === "string" ? item.replace(/\bBearer\s+[A-Za-z0-9._~-]+/gi, "Bearer [비공개]") : item;
  });
  return typeof value === "string" ? JSON.parse(serialized) : formatRawJson(serialized);
}

function caseComparisons(item, definition = {}, observed = {}) {
  const actual = {...observed, ...(item.analysis || {}), ...item};
  const expected = {...(definition.expected_values || {})};
  if (item.expected_status !== undefined) expected.http_status = item.expected_status;
  if (item.expected_response !== undefined) expected.response = item.expected_response;
  if (item.expected && typeof item.expected === "object" && !Array.isArray(item.expected)) {
    for (const [field, value] of Object.entries(item.expected)) {
      if (["string", "number", "boolean"].includes(typeof value) || value === null) expected[field] = value;
    }
  } else if (item.expected !== undefined) {
    expected[typeof item.decision === "string" ? "decision" : "actual"] = item.expected;
  }
  if (item.expected_action_id !== undefined) expected.action_id = item.expected_action_id;
  return Object.entries(expected).filter(([field]) => !gradingCredentialKey(field) && !/_(token|secret|password|capability)$/i.test(field)).map(([field, value]) => ({field, expected: value,
    actual: field === "http_status" ? actual.observed_status ?? actual.http_status
      : field === "response" ? actual.response ?? actual.returned ?? actual.reply ?? actual.bot_message
      : Object.hasOwn(actual,field) ? actual[field] : actual.actual && typeof actual.actual === "object" ? actual.actual[field] : undefined}));
}

function caseAnalysisIds(item) {
  const ids = []; const seen = new Set();
  function visit(value, depth = 0) {
    if (!value || typeof value !== "object" || depth > 7 || seen.has(value)) return;
    seen.add(value);
    for (const [key, child] of Object.entries(value)) {
      if (gradingCredentialKey(key) || /_(token|secret|password|capability)$/i.test(key)) continue;
      if (["request_id", "trace_id", "provider_request_id", "query_provider_request_id", "execution_id", "RequestId"].includes(key)
          && typeof child === "string" && /^[A-Za-z0-9._:-]{8,160}$/.test(child)
          && !ids.some(id => id.value === child)) ids.push({field: key, value: child});
      else if (typeof child === "object") visit(child, depth + 1);
      if (ids.length >= 12) return;
    }
  }
  visit(item);
  return ids;
}

function caseDisplayContext(item, payload = {}, problem = activeProblem) {
  const mission = caseCatalog[problem] || {};
  const definition = mission.cases?.[item.case_id] || {};
  const result = payload.result || {};
  const candidates = [result.receipt?.cases, result.execution?.cases, result.children,
    result.query_attempts, result.analysis_executions].filter(Array.isArray).flat()
    .filter(record => record && typeof record === "object");
  const matching = candidates.find(record => (item.case_id && record.case_id === item.case_id)
    || (item.request_id && record.request_id === item.request_id));
  let input;
  for (const source of [item, matching || {}]) {
    const key = ["input", "prompt", "request", "query", "message", "body"]
      .find(name => Object.hasOwn(source, name));
    if (key) { input = source[key]; break; }
  }
  if (input === undefined && problem === "P00") input = payload.received;
  if (input === undefined && (item.principal !== undefined || item.client_claims !== undefined)) {
    input = Object.fromEntries(["principal", "action", "client_claims"]
      .filter(key => item[key] !== undefined).map(key => [key, item[key]]));
  }
  const observations = {};
  if (["P14", "P15"].includes(problem) && item.case_id === "native-tool-report") observations.attempts = result.native_attempts;
  if (["P14", "P15"].includes(problem) && item.case_id === "execution-limits") observations.settings = result.config;
  if (problem === "P18") { observations.queries = result.queries; observations.query_attempts = result.query_attempts?.filter(row => row.request_id === item.request_id); }
  if (problem === "P20" && item.case_id === "alert-lifecycle") observations.requests = result.native_requests;
  if (problem === "P20" && item.case_id === "configuration-binding") observations.settings = item.configuration;
  if (problem === "P16" && item.case_id === "promotion-ledger") observations.events = result.events;
  const details = Object.fromEntries(Object.entries(observations).filter(([, value]) => value !== undefined));
  const observed = {...(matching || {})};
  const caseCalls = Array.isArray(result.provider_calls) ? result.provider_calls.filter(call => call.case_id === item.case_id) : [];
  if (["P07", "P08"].includes(problem) && Array.isArray(result.provider_calls) && Array.isArray(result.capabilities)) {
    const roles = problem === "P07" ? {guard_calls:"content_safety",main_calls:"main"} : {self_check_calls:"self_check_input",main_calls:"main"};
    for (const [field, role] of Object.entries(roles)) {
      const grant = result.capabilities.find(cap => cap.case_id === item.case_id && cap.role === role);
      if (grant && ["completed", "closed_unused"].includes(grant.status)) observed[field] = caseCalls.filter(call => call.role === role).length;
    }
  }
  const dynamicSummary = problem === "P13" ? `Promptfoo 고정 케이스「${item.case_id || item.name || "이름 없음"}」에 보낸 입력과 assertion·Application 응답을 비교합니다.`
    : problem === "P16" ? mission.cases?.[String(item.case_id).split(":").pop()]?.summary : undefined;
  return {...item, test_description: definition.summary || dynamicSummary || mission.summary,
    case_comparisons: caseComparisons(item, definition, observed),
    analysis_ids: caseAnalysisIds({...observed, ...item, provider_calls:caseCalls}),
    ...(input !== undefined ? {input} : {}),
    defined_request: JSON.stringify(input) !== JSON.stringify(definition.request) ? definition.request : undefined,
    test_observations: Object.keys(details).length ? details : undefined};
}

function createCaseCard(item, index) {
  item = {...(item.analysis ?? {}), ...item};
  const row = document.createElement("li");
  const status = item.status === "HIT" ? "HIT" : item.case_verified === true ? "PASS" : item.case_verified === false ? "ERR" : item.status ?? item.course_verdict ?? item.verdict ?? item.outcome ?? (item.analysis_correct === true ? "ANALYSIS PASS" : item.assertion_passed === true ? "ASSERTION PASS" : item.assertion_passed === false ? "ASSERTION FAIL" : "기록 확인");
  const tone = ["PASS", "ASSERTION PASS", "ANALYSIS PASS"].includes(status) ? "pass" : status === "HIT" ? "hit" : status === "ERR" ? "err" : "neutral";
  row.className = `case-card case-${tone}`;
  const heading = document.createElement("div"); heading.className = "case-card-heading";
  const title = document.createElement("strong"); title.textContent = `케이스 ${item.number ?? index + 1} · ${({"execution-limits":"실행 제한 확인","native-tool-report":"실제 도구 실행과 보고서 검증","normal-business":"정상 업무 요청","normal-explanation":"공격 문자열을 설명하는 정상 요청","risk-marker":"공격 표지 요청","risk-paraphrase":"표현을 바꾼 공격 요청","promotion-ledger":"정책 승격·되돌리기 원장","normal-lookup":"정상 공지 조회","unauthorized-publish":"권한 없는 공지 게시","anonymous-lookup":"인증되지 않은 공지 조회","normal-query":"정상 요청 기록 조회","denied-query":"거부 요청 기록 조회","0-collected":"정상 요청 기록 분석","0-reversed":"정상 요청 기록 순서 뒤집기","1-collected":"인가 거부 기록 분석","1-reversed":"인가 거부 기록 순서 뒤집기","2-collected":"인증 거부 기록 분석","2-reversed":"인증 거부 기록 순서 뒤집기","missing-log":"로그가 빠진 사본","foreign-trace":"다른 Trace가 섞인 사본","open-ledger":"끝나지 않은 처리 원장","duplicate-span":"Span이 중복된 사본","forbidden-model":"금지 모델 호출","untrusted-server":"허용하지 않은 MCP 서버","forbidden-tool":"허용하지 않은 도구","tool-loop":"도구 호출 횟수 초과","oversized-result":"도구 결과 크기 초과","tool-timeout":"도구 응답 시간 초과","foreign-state":"다른 Agent의 상태 접근","wrong-audience":"다른 서버용 인증 정보","configuration-binding":"설정 파일과 실제 적용 상태","alert-lifecycle":"실제 경보 발생·해제","no-approval":"승인 없는 공지 게시","self-approval":"요청자의 자기 승인","changed-args":"승인 뒤 게시 내용 변경","expired":"만료된 승인 사용","approved":"정확한 승인으로 한 번 게시","reuse":"사용한 승인 재사용"})[item.case_id] ?? item.case_id ?? item.id ?? item.name ?? item.request_id ?? "실행 기록"}`;
  const badge = document.createElement("span"); badge.className = `case-badge ${tone}`; badge.textContent = String(status);
  heading.append(title, badge);
  if (item.started_at || item.elapsed_seconds !== undefined) {
    const elapsed = document.createElement("span"); elapsed.className = "case-elapsed";
    if (item.started_at) elapsed.dataset.startedAt = typeof item.started_at === "number" ? new Date(item.started_at * 1000).toISOString() : item.started_at;
    elapsed.textContent = item.elapsed_seconds !== undefined ? `${item.elapsed_seconds}초` : "대기 0초";
    heading.append(elapsed);
  }

  const cue = document.createElement("p"); cue.className = "case-cue";
  cue.textContent = {pass: "통과! 이 케이스의 기대 동작을 확인했습니다.", hit: "공격 영향 발견! 실행 기록에서 영향을 확인하세요.", err: "확인이 멈췄습니다. 오류와 다음 확인 안내를 살펴보세요.", neutral: "실행 기록 도착! 아래 근거를 확인하세요."}[tone];
  if (["실행 중", "채점 중", "결과 조회 중"].includes(status)) cue.textContent = "서버 응답을 기다리고 있습니다. 막대는 진행 중 표시이며 완료 비율을 뜻하지 않습니다.";
  if (status === "ANALYSIS PASS") cue.textContent = item.input_kind === "damaged_copy"
    ? "분석 통과! 손상된 기록을 올바르게 거부했습니다." : "분석 통과! 같은 요청의 기록과 실행 순서가 일치합니다.";
  if (status === "ASSERTION PASS") cue.textContent = "검사 통과! 설정한 assertion과 실제 응답이 일치했습니다.";
  if (tone === "neutral" && item.decision === "block") cue.textContent = "차단 실행! 멈춘 단계와 뒤 호출 기록을 확인하세요.";
  if (tone === "neutral" && item.decision === "allow") cue.textContent = "처리 완료! 허용 경로와 실제 호출 기록을 확인하세요.";
  const evidence = document.createElement("small");
  evidence.textContent = item.observed_status !== undefined && item.expected_status !== undefined
    ? `HTTP ${item.observed_status} / 기대 ${item.expected_status} · HTTP 비교 결과입니다.`
    : ["outcome", "decision", "http_status", "case_verified", "provider_attempts", "calls", "provider_calls", "tool_calls", "upstream_called", "stop_reason", "guard_calls", "main_calls", "stop", "main_capability_status", "self_check_calls", "downstream_count", "retrieval_count", "stop_stage", "assertion_passed", "success", "native_status", "score", "is_error", "denied", "effect_count", "reason", "result_bytes", "analysis_correct", "input_kind"]
        .filter(key => item[key] !== undefined && ["string", "number", "boolean"].includes(typeof item[key]))
        .map(key => `${key}=${item[key]}`).join(" · ") || String(item.reason ?? item.detail ?? "상세 요청·응답은 RAW 응답에서 확인하세요.");
  const details = [];
  for (const key of ["stages", "spans", "detector_results"]) {
    if (item[key] !== undefined) details.push(`${key}=${JSON.stringify(item[key])}`);
  }
  if (details.length) evidence.textContent += ` · ${details.join(" · ")}`;
  const caseDetails = document.createElement("details"); caseDetails.className = "case-details";
  const toggle = document.createElement("summary"); toggle.textContent = "상세 보기";
  caseDetails.append(toggle, cue, evidence);
  row.append(heading, caseDetails);
  if (["실행 중", "채점 중", "결과 조회 중"].includes(status)) {
    const bar = document.createElement("progress"); bar.className = "case-running-bar";
    bar.setAttribute("aria-label", `${title.textContent} ${status}`);
    caseDetails.before?.(bar);
  }
  if (item.case_comparisons?.length) {
    const wrapper = document.createElement("div"); wrapper.className = "case-comparison";
    const table = document.createElement("table");
    const caption = document.createElement("caption"); caption.textContent = "기대값과 실제값 비교"; table.append(caption);
    const head = document.createElement("tr");
    for (const label of ["검사 항목", "기대값", "실제값"]) { const cell = document.createElement("th"); cell.scope = "col"; cell.textContent = label; head.append(cell); }
    const thead = document.createElement("thead"); thead.append(head); table.append(thead);
    const body = document.createElement("tbody");
    const labels = {http_status:"HTTP 상태", main_calls:"Main 호출", guard_calls:"위해 검사 호출", self_check_calls:"Self-check 호출", downstream_count:"뒤 서비스 호출", decision:"처리 결정", action_id:"실행 Action", response:"응답", actual:"검사 결과"};
    for (const comparison of item.case_comparisons) {
      const tr = document.createElement("tr");
      for (const value of [labels[comparison.field] || comparison.field, comparison.expected, comparison.actual]) {
        const cell = document.createElement("td"); cell.textContent = value === undefined ? "기록 없음" : displayCaseValue(value); tr.append(cell);
      }
      body.append(tr);
    }
    table.append(body); wrapper.append(table); caseDetails.append(wrapper);
  }
  if (item.analysis_ids?.length) {
    const block = document.createElement("div"); block.className = "case-analysis-ids";
    const label = document.createElement("strong"); label.textContent = "분석 ID"; block.append(label);
    for (const id of item.analysis_ids) {
      const line = document.createElement("div"); line.className = "case-id-row";
      const text = document.createElement("code"); text.textContent = `${id.field}: ${id.value}`;
      const copy = document.createElement("button"); copy.type = "button"; copy.className = "case-copy-id";
      copy.textContent = "복사"; copy.setAttribute("aria-label", `${id.field} ${id.value} 복사`);
      copy.addEventListener("click", async () => {
        try { await navigator.clipboard.writeText(id.value); copy.textContent = "복사됨"; }
        catch { copy.textContent = "복사 실패"; }
      });
      line.append(text, copy); block.append(line);
    }
    caseDetails.append(block);
  }
  const fields = [
    ["검사 내용", item.test_description],
    ["실행 로그", item.execution_log],
    ["실제 요청·입력", Object.hasOwn(item, "input") ? item.input : item.prompt ?? item.request ?? item.query ?? item.message],
    ["케이스에 정의된 요청", item.defined_request],
    ["실행 기록·공격 시도", item.test_observations],
    ["기대 동작", item.expected ?? item.expected_response ?? (item.expected_status !== undefined ? {http_status: item.expected_status} : undefined)],
    ["실제 결과", item.response ?? item.returned ?? item.reply ?? item.bot_message ?? item.actual],
    ["처리 경로", item.dialog_path],
    ["오류", item.error],
    ["다음 확인", item.next_check],
  ];
  if (item.diagnosis) {
    fields.unshift(["오류 원인", item.diagnosis.cause], ["수정할 파일", item.diagnosis.file], ["확인할 설정", item.diagnosis.field], ["멈춘 단계", item.diagnosis.stopped_stage], ["모델 호출 기록", item.diagnosis.model_calls], ["다음 행동", item.diagnosis.next_action], ["실행 로그 확인", item.diagnosis.log_command]);
  }
  for (const [label, value] of fields) {
    if (value === undefined) continue;
    const block = document.createElement("div"); block.className = "case-detail";
    const name = document.createElement("strong"); name.textContent = label;
    const content = document.createElement("pre");
    content.textContent = displayCaseValue(value);
    block.append(name, content); caseDetails.append(block);
  }
  return row;
}

function renderReportedCases(payload) {
  byId("case-progress").hidden = true;
  byId("case-progress-list").replaceChildren();
  let cases = payload.result?.cases ?? payload.result?.receipt?.cases ?? payload.result?.analyses ?? payload.cases;
  if (!Array.isArray(cases)) {
    const names = ["P22", "H22"].includes(payload.activity_id)
      ? ["normal", "no_approval", "self_approval", "changed_args", "expired", "approved", "reuse"] : ["normal", "risk"];
    const effectIndexes = {no_approval: 0, changed_args: 1, expired: 2, approved: 3, reuse: 4};
    cases = names.filter(key => payload.result?.[key] && typeof payload.result[key] === "object" && !Array.isArray(payload.result[key]))
      .map(key => ({case_id: ({normal: "정상 요청", risk: "위험 요청", no_approval: "승인 없음", self_approval: "자기 승인", changed_args: "승인 후 인자 변경", expired: "만료된 승인", approved: "정확한 승인", reuse: "승인 재사용"})[key], ...payload.result[key], ...(payload.result.effect_counts?.[effectIndexes[key]] !== undefined ? {effect_count: payload.result.effect_counts[effectIndexes[key]]} : {})}));
  }
  if (["P19", "H19"].includes(payload.activity_id) && Array.isArray(payload.result?.checks)) cases = payload.result.checks;
  const list = byId("case-results-list"); list.replaceChildren();
  byId("case-results").hidden = !Array.isArray(cases) || cases.length === 0;
  if (Array.isArray(cases)) cases.forEach((item, index) => list.append(createCaseCard(caseDisplayContext(item, payload), index)));
}

function updateCaseElapsed() {
  document.querySelectorAll(".case-elapsed[data-started-at]").forEach(node => {
    const seconds = Math.max(0, Math.floor((Date.now() - Date.parse(node.dataset.startedAt)) / 1000));
    node.textContent = `대기 ${seconds}초`;
  });
}

function showGradingWait(problem, startedAt) {
  missionResults.delete(problem);
  try { sessionStorage.removeItem(`guided-grading-result-${problem}`); } catch {}
  if (problem === "P00") {
    setText("tutorial-checked-at", "이번 채점을 진행하고 있습니다.");
  } else {
    byId("case-results-list").replaceChildren();
    byId("case-results").hidden = true;
    byId("grading-checked-at").hidden = true;
    byId("raw").closest("details").open = false;
  }
  const target = problem === "P00" ? byId("tutorial-cases") : byId("case-progress-list");
  target.replaceChildren();
  if (problem === "P00") {
    for (const name of ["JSON 객체 형식", "필드 이름과 개수", "질문 문장", "출력 상한의 자료형과 값"]) {
      target.append(createCaseCard({case_id: name, status: "결과 조회 중", started_at: startedAt}, target.children.length));
    }
  } else {
    target.append(createCaseCard({case_id: "테스트 케이스 묶음", status: "채점 중", started_at: startedAt}, 0));
    byId("case-progress").hidden = false;
    setText("case-progress-phase", "실행 및 증거 대조 중");
  }
}

function renderCaseProgress(progress) {
  byId("case-results").hidden = true;
  byId("case-progress").hidden = false;
  const list = byId("case-progress-list");
  list.replaceChildren();
  for (const item of progress.cases || []) {
    list.append(createCaseCard(caseDisplayContext(item), list.children.length));
  }
  if (progress.current_case) list.append(createCaseCard(caseDisplayContext(progress.current_case), list.children.length));
  const labels = {running: "케이스 실행 중", verifying: "케이스 실행 완료 · 증거 대조 중", finished: "실행 종료", idle: "시작 대기"};
  setText("case-progress-phase", `${labels[progress.phase] || "시작 대기"} · ${progress.total ? `${(progress.cases || []).length}/${progress.total}` : `완료 ${(progress.cases || []).length}건`}${progress.verdict ? ` · 최종 ${progress.verdict}` : ""}`);
}

function selectP01Pane(name) {
  for (const item of ["model", "grade"]) {
    const selected = item === name;
    byId(`p01-${item}-panel`).hidden = !selected;
    byId(`p01-${item}-tab`).setAttribute("aria-selected", String(selected));
    byId(`p01-${item}-tab`).tabIndex = selected ? 0 : -1;
  }
}

async function checkModelConnection() {
  if (executionPending) return;
  setBusy(true, false);
  setText("model-connection-status", "Nova Lite 연결을 확인하고 있습니다.");
  byId("model-connection-details").hidden = true;
  try {
    const payload = await request("/api/provider-preflight");
    const verdict = payload.security_verdict || payload.course_verdict;
    setText("model-connection-status", verdict === "PASS" ? "Nova Lite 연결을 확인했습니다." : "연결 확인을 완료하지 못했습니다. 연결 확인 기록을 살펴보세요.");
    setText("model-connection-raw", JSON.stringify(payload, null, 2));
  } catch (error) {
    setText("model-connection-status", "연결 확인 중 오류가 발생했습니다. 연결 확인 기록을 살펴보세요.");
    setText("model-connection-raw", JSON.stringify(error.detail || error.message, null, 2));
  } finally {
    byId("model-connection-details").hidden = false;
    setBusy(false, false);
  }
}

async function execute(path, body) {
  if (executionPending) return;
  const selectedProblem = path.match(/\/practice\/(P\d{2})\//)?.[1];
  if (selectedProblem && homeMissions.some(item => item.id === selectedProblem)) {
    activeProblem = selectedProblem; renderBreadcrumb(activeProblem);
    setText("current-station", missionLabel(activeProblem));
    setText("activity-label", `PRACTICE · ${missionLabel(activeProblem)}`);
    setText("activity-title", homeMissions.find(item => item.id === activeProblem).title);
  }
  progressRequest++;
  showMissionResults();
  setBusy(true);
  const resourceAction = /\/(provision|delete-resources)$/.test(path);
  const deletingResources = path.endsWith("/delete-resources");
  const operationPanel = byId("resource-operation");
  operationPanel.hidden = !resourceAction;
  if (resourceAction) {
    byId("resource-raw-details").hidden = true;
    const total = resourceTotals[selectedProblem]?.[deletingResources ? "delete" : "prepare"] || 1;
    byId("resource-operation-bar").max = total;
    byId("resource-operation-bar").value = 0;
    setText("resource-operation-count", `0 / ${total}`);
    setText("resource-operation-label", deletingResources ? "AWS 자원 삭제 중" : "AWS 자원 준비 중");
    setText("resource-operation-detail", "서버에서 AWS 작업을 진행하고 있습니다.");
    document.querySelector(".inspection").hidden = true;
    document.querySelector(".receipt").hidden = true;
    byId("case-results").hidden = true;
  }
  const started = Date.now();
  setText("request-status", "요청을 보냈습니다. 서버 응답을 기다립니다. 다시 누르지 않아도 됩니다.");
  byId("request-elapsed").hidden = !resourceAction;
  const updateElapsed = () => { updateCaseElapsed(); setText("request-elapsed", `대기 ${Math.floor((Date.now() - started) / 1000)}초 · 경과 시간은 진행률이 아닙니다. 창을 닫아도 서버 작업이 취소되지는 않습니다.`); };
  updateElapsed();
  executionTimer = setInterval(updateElapsed, 1000);
  byId("task-completion").hidden = true;
  byId("failure-help").hidden = true;
  const problem = path.match(/^\/api\/practice\/(P\d{2})\/verify$/)?.[1];
  if (problem === "P01") selectP01Pane("grade");
  const affectedProblem = problem;
  if (affectedProblem) {
    if (completedPractices.has(affectedProblem)) recheckPractices.set(affectedProblem, "새 검증이나 준비를 시작했습니다.");
    completedPractices.delete(affectedProblem);
    renderPracticeProgress();
  }
  byId("verdict").className = "verdict empty";
  byId("verdict").querySelector("strong").textContent = "—";
  byId("verdict").querySelector("span").textContent = "응답 대기";
  for (const id of ["execution-id", "source-digest", "verified-by", "provider-id", "model-id", "requested-max", "forwarded-max", "output-tokens", "reason", "next-check"]) setText(id, null);
  setText("raw", "이번 요청의 응답을 기다립니다. 이전 응답은 이번 실행의 증거가 아닙니다.");
  let resourceTimer = null;
  let resourceStopped = false;
  let previousResourceOperation = null;
  const pollResource = async () => {
    try {
      const response = await fetch(`/api/resource-progress/${selectedProblem}`);
      if (response.ok) {
        const progress = await response.json();
        if (!resourceStopped && progress.operation_id && progress.operation_id !== previousResourceOperation) renderResourceProgress(progress);
      }
    } catch (_) { /* The action response remains authoritative. */ }
    finally { if (!resourceStopped) resourceTimer = setTimeout(pollResource, 600); }
  };
  let progressTimer = null;
  let progressStopped = false;
  let previousSuite = null;
  byId("case-progress").hidden = !problem;
  if (problem) showGradingWait(problem, new Date(started).toISOString());
  const pollProgress = async () => {
    try {
      const response = await fetch(`/api/test-progress/${problem}`);
      if (!response.ok) return;
      const progress = await response.json();
      if (!progressStopped && progress.suite_id && progress.suite_id !== previousSuite) renderCaseProgress(progress);
    } catch (_) { /* The verification response remains the authoritative result. */ }
    finally {
      if (!progressStopped) progressTimer = setTimeout(pollProgress, 500);
    }
  };
  try {
    if ((problem && problem !== "P03")) {
      renderCaseProgress({phase: "idle", cases: [], total: problem === "P04" ? 27 : problem === "P02" ? 22 : problem === "P01" ? 23 : problem === "P23" ? 3 : null});
      try {
        const snapshot = await fetch(`/api/test-progress/${problem}`);
        if (snapshot.ok) previousSuite = (await snapshot.json()).suite_id;
      } catch (_) { /* Verification can proceed if progress polling is unavailable. */ }
      progressTimer = setTimeout(pollProgress, 100);
    }
    if (resourceAction) {
      try {
        const snapshot = await fetch(`/api/resource-progress/${selectedProblem}`);
        if (snapshot.ok) previousResourceOperation = (await snapshot.json()).operation_id;
      } catch (_) { /* Continue the action if progress polling is unavailable. */ }
      resourceTimer = setTimeout(pollResource, 150);
    }
    const payload = await request(path, body);
    progressStopped = true;
    clearTimeout(progressTimer);
    if (problem) byId("case-progress").hidden = true;
    if (!resourceAction && path.endsWith("/verify") && payload.activity_id?.startsWith("P")) cacheGradingResult(payload.activity_id, payload, started);
    showMissionResults();
    renderEnvelope(payload);
    if (resourceAction) {
      renderResourceProgress(payload.resource_progress);
      setText("resource-operation-label", deletingResources ? "AWS 자원 삭제 완료" : "AWS 자원 준비 완료");
      setText("resource-operation-detail", "미션은 아직 채점하지 않았습니다. " + payload.next_check);
    }
    setText("request-status", "응답을 받았습니다. 준비 결과와 과제 완료·보안 판정은 아래 기록에서 구분해 확인하세요.");
    if (problem) {
      renderLearningSupport(payload, problem);
      recordPracticeCompletion(payload, problem);
    }
  } catch (error) {
    progressStopped = true;
    clearTimeout(progressTimer);
    if (problem) byId("case-progress").hidden = true;
    renderError(error);
    if (resourceAction) {
      operationPanel.hidden = false;
      for (const {node} of p01ResultHomes) node.hidden = true;
      setText("resource-raw", JSON.stringify(error.detail || error.message, null, 2));
      byId("resource-raw-details").hidden = false;
      setText("resource-operation-label", "AWS 작업 완료 여부를 확인하세요");
      setText("resource-operation-detail", "RAW 오류를 확인하세요. 일부 자원이 생성되거나 삭제되었을 수 있습니다.");
      document.querySelector(".inspection").hidden = true;
      document.querySelector(".receipt").hidden = true;
    }
    setText("request-status", "응답 오류로 결과를 확정하지 못했습니다. 원시 오류를 확인하세요. 서버 작업이 끝났는지는 별도로 확인해야 합니다.");
    if (problem) renderLearningSupport({...error.detail, http_status: error.httpStatus, course_verdict: "ERR"}, problem);
  } finally {
    resourceStopped = true;
    clearTimeout(resourceTimer);
    progressStopped = true;
    clearTimeout(progressTimer);
    clearInterval(executionTimer);
    executionTimer = null;
    byId("request-elapsed").hidden = true;
    setBusy(false);
  }
}

let viewReady = false;
const viewStorageKey = "guided-current-view";
function saveCurrentView() {
  if (!viewReady) return;
  const workspace = !byId("home-panel").hidden ? "home" : !byId("tutorial-panel").hidden ? "tutorial" : "missions";
  const pane = workspace === "tutorial" ? (byId("tutorial-grade-tab").getAttribute("aria-selected") === "true" ? "grade" : "experience")
    : activeProblem === "P01" ? (byId("p01-grade-tab").getAttribute("aria-selected") === "true" ? "grade" : "experience")
    : byId("h23-grade-tab").getAttribute("aria-selected") === "true" ? "grade" : "experience";
  const scroll = {};
  for (const id of ["mission-guidance", "mission-execution", "tutorial-panel"]) scroll[id] = byId(id)?.scrollTop || 0;
  try { sessionStorage.setItem(viewStorageKey, JSON.stringify({workspace, problem:activeProblem, pane, scroll, y:window.scrollY})); } catch {}
}
function restoreCurrentView() {
  let view;
  try { view = JSON.parse(sessionStorage.getItem(viewStorageKey)); } catch { return; }
  if (!view || !["home", "tutorial", "missions"].includes(view.workspace)) return;
  if (!["experience", "grade"].includes(view.pane)) return;
  if (view.workspace === "missions") {
    const index = practiceGroups.findIndex(group => group.includes(view.problem));
    if (index < 0) return;
    selectTab(index, view.problem);
    if (view.problem === "P01") selectP01Pane(view.pane === "grade" ? "grade" : "model");
    else selectModelCallPane(view.pane);
  } else {
    selectWorkspace(view.workspace);
    if (view.workspace === "tutorial") selectTutorialPane(view.pane);
  }
  requestAnimationFrame(() => {
    if (Number.isFinite(view.y) && view.y >= 0) window.scrollTo(0, view.y);
    for (const id of ["mission-guidance", "mission-execution", "tutorial-panel"])
      if (Number.isFinite(view.scroll?.[id]) && view.scroll[id] >= 0 && byId(id)) byId(id).scrollTop = view.scroll[id];
  });
}
window.addEventListener("pagehide", saveCurrentView);
document.addEventListener("visibilitychange", () => { if (document.visibilityState === "hidden") saveCurrentView(); });

async function bootstrap() {
  renderTabs();
  setMissionMenu(sidebarPinned && window.matchMedia("(min-width: 761px)").matches);
  renderPracticeProgress();
  const response = await fetch("/api/bootstrap");
  if (!response.ok) throw new Error("세션을 시작하지 못했습니다.");
  const payload = await response.json();
  csrfToken = payload.csrf_token;
  adminMode = payload.admin_mode === true;
  if (adminMode) history.replaceState(history.state, "", "/?mode=admin");
  const catalogResponse = await fetch("/api/case-catalog");
  if (catalogResponse.ok) caseCatalog = await catalogResponse.json();
  resourceTotals = payload.resource_total_steps || {};
  setText("tutorial-submit-command", `curl -sS -X POST '${location.origin}/api/practice/P00/check' \\
  -H 'Authorization: Bearer ${payload.p00_submission_token}' \\
  -H 'Content-Type: application/json' \\
  --data-binary @"$HOME/work/control-center-tutorial/request.json" | jq`);
  renderOfficialUis(payload.official_uis);
  prepareMissionPanes();
  prepareAdminAnswers();
  prepareCopyableBlocks();
  applyMissionDisplayLabels();
  restoreGradingResults();
  selectTab(0);
  selectWorkspace("home");
  renderSidebarPin();
  await restorePracticeProgress();
  const tutorialResponse = await fetch("/api/practice/P00/result");
  if (tutorialResponse.ok) {
    const result = await tutorialResponse.json();
    recordTutorialCompletion(result);
    let cached = false;
    try { cached = !!sessionStorage.getItem("guided-grading-result-P00"); } catch {}
    if (!cached) displayTutorialGrade(result);
  }
  restoreCurrentView();
  viewReady = true;
}

byId("completion-dismiss").addEventListener("click", dismissCelebration);
document.addEventListener("keydown", event => {
  if (event.key === "Escape") dismissCelebration();
});

byId("preflight").addEventListener("click", checkModelConnection);
byId("verify").addEventListener("click", () => execute("/api/practice/P01/verify"));
byId("h02-delete").addEventListener("click", () => {
  if (executionPending) return;
  const resources = "S3 원문, 벡터 인덱스, Knowledge Base, 전용 IAM 역할";
  if (window.confirm(`${missionLabel("P02")}의 ${resources}을 삭제하시겠습니까? 원문·검색 데이터는 삭제되고 작성한 코드는 유지됩니다.`)) execute("/api/practice/P02/delete-resources");
});
byId("h02-provision").addEventListener("click", () => execute("/api/practice/P02/provision"));
byId("h02-verify").addEventListener("click", () => execute("/api/practice/P02/verify"));
byId("h03-delete").addEventListener("click", () => {
  if (executionPending) return;
  const resources = "S3 원문, 벡터 인덱스, Knowledge Base, 전용 IAM 역할";
  if (window.confirm(`${missionLabel("P03")}의 ${resources}을 삭제하시겠습니까? 원문·검색 데이터는 삭제되고 작성한 코드는 유지됩니다.`)) execute("/api/practice/P03/delete-resources");
});
byId("h03-provision").addEventListener("click", () => execute("/api/practice/P03/provision"));
byId("h03-verify").addEventListener("click", () => execute("/api/practice/P03/verify"));
byId("h04-delete").addEventListener("click", () => {
  if (executionPending) return;
  const resources = "전용 Guardrail DRAFT";
  if (window.confirm(`${missionLabel("P04")}의 ${resources}을 삭제하시겠습니까? 원문·검색 데이터는 삭제되고 작성한 코드는 유지됩니다.`)) execute("/api/practice/P04/delete-resources");
});
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
window.addEventListener("focus", () => {
  if (csrfToken && !executionPending) restorePracticeProgress();
});

applyTheme(readThemeMode());
bootstrap().catch(renderError);

for (const [index, name] of ["home", "missions"].entries()) {
  byId(`workspace-${name}`).addEventListener("click", () => name === "missions" ? selectTab(activeTab, activeProblem) : selectWorkspace(name));
  byId(`workspace-${name}`).addEventListener("keydown", event => {
    const names = ["home", "missions"];
    if (["ArrowRight", "ArrowLeft", "Home", "End"].includes(event.key)) {
      event.preventDefault();
      const next = event.key === "Home" ? 0 : event.key === "End" ? 1 : 1 - index;
      if (names[next] === "missions") selectTab(activeTab, activeProblem); else selectWorkspace(names[next]);
      byId(`workspace-${names[next]}`).focus();
    }
  });
}
byId("mission-menu-toggle").addEventListener("click", () => {
  const open = byId("mission-menu").hidden;
  setSidebarPinned(open); setMissionMenu(open);
});
for (const id of ["mission-menu-backdrop"]) byId(id).addEventListener("click", () => {setSidebarPinned(false); setMissionMenu(false); byId("mission-menu-toggle").focus();});
byId("p00-menu").addEventListener("click", () => selectWorkspace("tutorial"));
byId("p00-menu").addEventListener("keydown", handleMissionMenuKey);
document.addEventListener("keydown", event => {
  if (byId("mission-menu").hidden) return;
  if (event.key === "Escape") {setSidebarPinned(false); setMissionMenu(false); byId("mission-menu-toggle").focus();}
  if (event.key === "Tab") {
    const controls = [...byId("mission-menu").querySelectorAll("button:not(:disabled)")];
    const first = controls[0], last = controls[controls.length - 1];
    if (event.shiftKey && document.activeElement === first) {event.preventDefault(); last.focus();}
    else if (!event.shiftKey && document.activeElement === last) {event.preventDefault(); first.focus();}
  }
});
function selectTutorialPane(name) {
  for (const pane of ["experience", "grade"]) {
    const selected = name === pane;
    const tab = byId(`tutorial-${pane}-tab`);
    tab.setAttribute("aria-selected", String(selected));
    tab.tabIndex = selected ? 0 : -1;
    byId(`tutorial-${pane}-panel`).hidden = !selected;
  }
}
for (const pane of ["experience", "grade"]) {
  byId(`tutorial-${pane}-tab`).addEventListener("click", () => selectTutorialPane(pane));
}
async function refreshTutorialResult(celebrate = false) {
  const started = Date.now();
  const button = byId("tutorial-grade-check");
  if (celebrate && button.disabled) return;
  let timer = null;
  if (celebrate) {
    button.disabled = true;
    showGradingWait("P00", new Date().toISOString());
    setText("tutorial-grade-status", "제출한 요청의 검사 결과를 확인하고 있습니다.");
    timer = setInterval(updateCaseElapsed, 1000);
  }
  try {
    const response = await fetch("/api/practice/P00/result");
    if (!response.ok) throw new Error("제출 결과를 조회하지 못했습니다. 화면을 새로고침하세요.");
    const result = await response.json();
    if (celebrate) {
      cacheGradingResult("P00", result, started);
      displayTutorialGrade(result);
      recordTutorialCompletion(result, true);
    }
    setText("tutorial-received", result.received !== undefined ? JSON.stringify(result.received, null, 2) : (result.completed ? "완료 기록이 저장되어 있습니다. 요청을 다시 제출하면 받은 JSON을 확인할 수 있습니다." : "아직 확인할 JSON 요청이 없습니다."));
    setText("tutorial-status", result.received !== undefined ? "서버가 받은 JSON 원본입니다. 작성한 파일과 대조하세요." : "표시할 요청 원본이 없습니다. 왼쪽 명령으로 파일을 제출하세요.");
  } catch (error) { setText(celebrate ? "tutorial-grade-status" : "tutorial-status", error.message);
    if (celebrate) displayTutorialGrade({completed: false, feedback: error.message});
  } finally { clearInterval(timer); if (celebrate) button.disabled = false; }
}
byId("tutorial-check").addEventListener("click", () => refreshTutorialResult());
byId("tutorial-grade-check").addEventListener("click", () => refreshTutorialResult(true));

byId("breadcrumb-category").addEventListener("click", () => {
  const category = document.querySelector(`.tab[data-problem="${activeProblem}"]`).closest(".mission-category");
  category.open = true; setMissionMenu(true); category.querySelector("summary").focus();
});
byId("breadcrumb-home").addEventListener("click", () => selectWorkspace("home"));
byId("navigation-home").addEventListener("click", () => selectWorkspace("home"));
byId("home-tutorial").addEventListener("click", () => selectWorkspace("tutorial"));
byId("home-next").addEventListener("click", () => {
  const problem = byId("home-next").dataset.problem;
  if (problem) selectTab(practiceGroups.findIndex(group => group.includes(problem)), problem);
  else setMissionMenu(true);
});
for (const [index, name] of ["model", "grade"].entries()) {
  byId(`p01-${name}-tab`).addEventListener("click", () => selectP01Pane(name));
  byId(`p01-${name}-tab`).addEventListener("keydown", event => {
    if (["ArrowLeft", "ArrowRight", "Home", "End"].includes(event.key)) {
      event.preventDefault();
      const next = event.key === "Home" ? "model" : event.key === "End" ? "grade" : index === 0 ? "grade" : "model";
      selectP01Pane(next); byId(`p01-${next}-tab`).focus();
    }
  });
}

byId("h23-verify").addEventListener("click", () => execute("/api/practice/P23/verify"));


const experienceFunctions = {
  P02:["문서 저장·임베딩", "입력 검사, 원문 저장, 임베딩 호출을 현재 함수로 실행합니다."],
  P03:["문서 동기화·검색", "현재 동기화 작업의 상태에 따라 검색이 호출되는지 확인합니다."],
  P04:["관리형 Guardrail 모델", "AWS 자원 관리에서 이메일 보호 정책을 준비하고 상태를 확인하세요. 정상·이메일 입력 시나리오는 미션 채점 결과 탭의 미션 채점 버튼으로 실행합니다."],
  P05:["Dialog Rail 모델", "입력한 상담 질문 한 건을 현재 Colang 흐름으로 처리합니다."],
  P06:["Python Action", "조회·송금 요구·우회 이름·범위 밖 요청에 현재 Action 정책을 적용합니다."],
  P07:["일반 위해 Self-check 모델", "현재 입력 검사와 Main Model 호출 흐름을 실행합니다."],
  P08:["업무 Self-check 모델", "현재 업무 입력 정책이 정상·위험 요청을 어떻게 처리하는지 실행합니다."],
  P09:["개인정보 처리·전달", "입력한 문장에서 개인정보를 찾고 현재 정책의 처리 결과를 확인합니다."],
  P10:["출력 Self-check 모델", "모델 출력에 현재 출력 정책을 적용하고 외부 전달 결과를 확인합니다."],
  P11:["문서 권한·출처 검색", "현재 검색 정책으로 사용자가 접근할 문서를 선택합니다."],
  P12:["Application 요청", "현재 인증·인가·검색·가드레일·모델 경로에 준비된 요청을 보냅니다."],
  P13:["Promptfoo 시나리오", "현재 작성한 평가 설정을 실행하고 도구의 원래 결과를 확인합니다."],
  P14:["Garak 스캔", "현재 스캔 설정으로 후보를 실행하고 보고서를 확인합니다."],
  P15:["PyRIT 시나리오", "현재 재현 코드로 공격 후보를 실행하고 실제 응답을 확인합니다."],
  P16:["정책 적용 비교", "입력한 문장에 현재 정책을 적용해 허용·차단 결정을 확인합니다. 승격과 Rollback 검사는 채점에서 실행합니다."],
  P17:["관측 신호 생성", "현재 계측 코드로 요청을 실행하고 Log·Trace·Metric 기록을 확인합니다."],
  P18:["관측 쿼리", "현재 작성한 쿼리로 관측 저장소를 조회합니다."],
  P19:["사건 연관 분석", "현재 분석 함수로 요청·공격자·Trace의 연결 결과를 확인합니다."],
  P20:["경보·Dashboard", "현재 설정으로 경보 수명주기와 Dashboard 연결을 실행합니다."],
  P21:["Agent 실행", "현재 정책으로 모델·도구 제안과 실제 도구 실행을 처리합니다."],
  P22:["MCP 승인·실행", "현재 승인 정책으로 승인 전후 호출과 실제 효과를 확인합니다."],
};
let experienceCatalog = {};
let nativeFormProblem = null;
const nativeDrafts = new Map();
const nativeActions = {P05:"상담 질문 보내기",P06:"선택한 Action 실행",P07:"입력 검사 후 답변 받기",P08:"업무 정책으로 답변 받기",P09:"개인정보 처리",P10:"출력 검사 후 답변 받기",P11:"권한을 적용해 문서 검색",P12:"Application 요청 보내기",P13:"Promptfoo 평가 실행",P14:"Garak 스캔 시작",P15:"공격 후보 재현",P16:"문장에 정책 적용",P17:"관측 신호 생성",P18:"작성한 쿼리 실행",P19:"사건 분석 실행",P20:"경보와 Dashboard 확인",P21:"선택한 Agent 요청 실행",P22:"선택한 MCP 요청 실행"};
function configureNativeInputs(problem) {
  const config=experienceCatalog[problem];
  const host=byId("native-experience-inputs");host.hidden=!config || config.mode==="run";
  if (nativeFormProblem === problem) return;
  if (nativeFormProblem) nativeDrafts.set(nativeFormProblem, {message:byId("native-message").value, scenario:byId("native-scenario").value, stage:byId("native-stage").value});
  nativeFormProblem = config ? problem : null;
  if (!config) return;
  const scenario=["scenario","operation"].includes(config.mode);
  byId("native-scenario").hidden=byId("native-scenario-label").hidden=!scenario;
  byId("native-scenario").replaceChildren();
  for (const item of config.options || []) {
    const option=document.createElement("option");option.value=item.id;option.textContent=item.label;byId("native-scenario").append(option);
  }
  byId("native-message-label").textContent=config.label || "이번 요청 내용";
  byId("native-message").hidden=byId("native-message-label").hidden=config.mode==="run";
  byId("native-message").readOnly=config.mode==="scenario" && !config.editable;
  byId("native-message").value=config.message || config.options?.[0]?.input || "";
  byId("native-stage").hidden=byId("native-stage-label").hidden=problem!=="P09";
  byId("native-stage").value="input";
  const draft=nativeDrafts.get(problem);
  if(draft){
    byId("native-message").value=draft.message;
    if((config.options || []).some(item=>item.id===draft.scenario))byId("native-scenario").value=draft.scenario;
    byId("native-stage").value=draft.stage;
  }
}
byId("native-scenario").addEventListener("change",()=>{
  const config=experienceCatalog[activeProblem];
  if(config?.mode==="scenario")byId("native-message").value=config.options.find(item=>item.id===byId("native-scenario").value)?.input || "";
});
fetch("/api/experience-catalog").then(response=>{if(!response.ok)throw Error();return response.json();}).then(catalog=>{experienceCatalog=catalog;configureNativeInputs(activeProblem);}).catch(()=>setText("mission-experience-status","미션 입력을 불러오지 못했습니다. 화면을 새로고침하세요."));
function modelAnswerCard(reply,label="모델 답변",avatarLabel="AI") {
  const card=document.createElement("article");card.className="model-response-card";
  const head=document.createElement("header");head.className="model-response-head";
  const avatar=document.createElement("span");avatar.className="model-response-avatar";avatar.textContent=avatarLabel;avatar.setAttribute("aria-hidden","true");
  const title=document.createElement("strong");title.textContent=label;head.append(avatar,title);
  const body=document.createElement("div");body.className="model-response-body";body.textContent=reply;
  card.append(head,body);return card;
}
function showExperienceSummary(payload) {
  const host=byId("mission-experience-summary");host.replaceChildren();
  const base=payload.result;
  const records=base?.records ?? [base];
  function appendRow(row,index) {
    if(!row || row.direct_skipped)return;
    const original=row;
    if(activeProblem === "P06" && row.action_result)row={...row,...row.action_result};
    if(row.result && typeof row.result === "object" && !Array.isArray(row.result))row={...row,...row.result};
    if(row.details && typeof row.details === "object")row={...row.details,...row};
    const worker=row.lifecycle?.execution || row.execution?.execution || row.execution;
    if(worker && typeof worker === "object")row={...worker,...row};
    const returned=worker?.result;
    const reply=activeProblem === "P06" ? undefined : row.reply ?? row.bot_message ?? row.released_text ?? row.details?.released_text ?? returned?.reply ?? returned?.body?.reply ?? (typeof row.response==="string" ? row.response : undefined);
    const nativeOutput=returned?.output?.message?.content?.map(item=>item.text || "").join("");
    const card=typeof (reply ?? nativeOutput)==="string" ? modelAnswerCard(reply ?? nativeOutput, activeProblem === "P09" ? "처리된 문장" : activeProblem === "P05" ? "상담 답변" : "모델 답변", activeProblem === "P09" ? "PII" : "AI") : document.createElement("article");
    if(!card.className)card.className="native-result-card";
    if(reply===undefined && !nativeOutput){const title=document.createElement("strong");title.textContent=experienceCatalog[activeProblem]?.options?.find(item=>item.id===row.case_id)?.label ?? row.case_id ?? row.id ?? nativeActions[activeProblem] ?? `실행 결과 ${index+1}`;card.append(title);}
    const facts=document.createElement("dl");facts.className="native-result-facts";
    const labels={kind:"Action 결과",action_id:"실행한 Action",balance_before:"처리 전 잔액",balance_after:"처리 후 잔액",status:"실행 결과",execution_status:"기능 실행 상태",execution_error:"실행 오류",exit_code:"도구 종료 코드",reason:"처리 사유",score:"도구 점수",success:"도구 검사 결과",stop_reason:"응답 종료",main_called:"Main 호출",guard_calls:"입력 검사 호출",main_calls:"Main 호출",self_check_calls:"Self-check 호출",downstream_count:"뒤 서비스 호출",policy_rule:"적용 규칙",decision:"처리 결정",run_state:"실행 상태",selected_document_id:"검색된 문서",selected_source_uri:"문서 출처",selected_score:"검색 점수",provider_calls:"모델 호출",tool_calls:"도구 호출",effect_count:"실제 변경 횟수",is_error:"도구 오류",user_intent:"인식한 요청",bot_intent:"선택한 답변",flow:"실행한 흐름",source_digest:"적용 코드",trace_id:"Trace ID",request_id:"Request ID",upstream_called:"뒤 서비스 호출",stop_stage:"멈춘 단계"};
    for(const [key,label] of Object.entries(labels))if(row[key]!==undefined){const name=document.createElement("dt"),value=document.createElement("dd");name.textContent=label;value.textContent=String(row[key]);facts.append(name,value);}
    if(row.documents){for(const document of row.documents){const section=document.createElement("section");section.className="native-document";const title=document.createElement("strong");title.textContent=document.id || "검색 문서";const body=document.createElement("p");body.textContent=document.body || document.content || "";section.append(title,body);if(document.source_uri){const source=document.createElement("small");source.textContent=document.source_uri;section.append(source);}card.append(section);}
      if(!row.documents.length){const empty=document.createElement("p");empty.textContent="현재 요청에 제공할 문서가 없습니다.";card.append(empty);}}
    if(["not_implemented","error","ERR"].includes(row.execution_status || row.status)){
      const hint=document.createElement("p");hint.className="native-execution-error";
      hint.textContent=row.execution_status === "not_implemented" ? "Starter 함수가 아직 구현되지 않았습니다. 왼쪽의 파일을 완성하고 코드 적용하기 명령을 실행하세요." : "실행이 멈췄습니다. 처리 사유와 RAW 응답의 오류를 확인하세요.";card.append(hint);
    }
    if(row.content && Array.isArray(row.content)){const heading=document.createElement("strong");heading.textContent="MCP 도구 응답";card.append(heading);const body=document.createElement("p");body.className="model-response-body";body.textContent=row.content.map(item=>item.text || "").join("\n");card.append(body);}
    if(facts.children.length)card.append(facts);
    const details=document.createElement("details"),title=document.createElement("summary"),raw=document.createElement("pre");title.textContent="처리 내역 보기";raw.textContent=JSON.stringify(original,null,2);details.append(title,raw);card.append(details);host.append(card);
  }
  for(const record of records){
    let rows=record?.cases ?? record?.execution?.cases ?? record?.result?.cases;
    if(record?.artifact?.results?.results){
      appendRow(record.receipt,0);
      rows=record.artifact.results.results.map((item,index)=>({case_id:`Promptfoo 요청 ${index+1}`,input:item.vars?.prompt,reply:item.response?.output,success:item.success,score:item.score,error:item.error,details:item}));
    }else if(Array.isArray(record?.report)){
      appendRow(record.receipt,0);
      rows=record.report.filter(item=>item.entry_type==="attempt").map(item=>({...item,case_id:`Garak 시도 ${item.seq}`,reply:item.outputs?.map(output=>typeof output === "string" ? output : output.text).join("\n")}));
      if(!rows.length)rows=[{case_id:"Garak 스캔",status:"시도 없음",reason:"공격 시도 기록이 없습니다. 스캔 설정과 RAW 응답의 Probe 초기화 로그를 확인하세요."}];
    }else if(Array.isArray(record?.turns)){
      appendRow(record,0);rows=record.turns;
    }else if(Array.isArray(record?.analysis_executions)){
      rows=record.analysis_executions;
    }
    (Array.isArray(rows) && rows.length ? rows : [record]).forEach(appendRow);
  }
}

function selectModelCallPane(name, restore = true) {
  const experience = activeProblem !== "P01" && name === "experience";
  byId("h23-experience").hidden = !experience || activeProblem !== "P23";
  byId("mission-experience").hidden = !experience || activeProblem === "P23";
  for (const group of byId("mission-resource-actions").children) {
    group.hidden = group.dataset.problem !== activeProblem;
    if (!group.hidden) group.querySelector(".aws-resource-toolbar")?.after(byId("resource-operation"));
  }
  byId("guardrail-chat-form").hidden = !experience || activeProblem !== "P04";
  byId("knowledge-search-form").hidden = !experience || activeProblem !== "P03";
  byId("document-upload-form").hidden = !experience || activeProblem !== "P02";
  byId("document-s3-link").closest(".document-console-links").hidden = activeProblem !== "P02";
  byId("document-console-help").hidden = activeProblem !== "P02";
  byId("knowledge-console-links").hidden = activeProblem !== "P03";
  byId("mission-experience-run").hidden = ["P02", "P03", "P04"].includes(activeProblem);
  byId("mission-experience-intro").hidden = ["P02", "P03", "P04"].includes(activeProblem);
  byId("mission-experience-run").nextElementSibling.hidden = ["P02", "P03", "P04"].includes(activeProblem);
  configureNativeInputs(activeProblem);
  const feature = experienceFunctions[activeProblem];
  setText("h23-experience-tab", activeProblem === "P23" ? "모델 직접 테스트" : "기능 직접 테스트");
  setText("mission-experience-intro", feature ? feature[1] : "현재 함수로 질문을 보내 모델 답변을 확인합니다.");
  setText("mission-experience-run", nativeActions[activeProblem] || "현재 기능 실행");
  byId("h23-experience-tab").setAttribute("aria-selected", String(experience));
  byId("h23-grade-tab").setAttribute("aria-selected", String(!experience));
  byId("h23-experience-tab").tabIndex = experience ? 0 : -1;
  byId("h23-grade-tab").tabIndex = experience ? -1 : 0;
  const actions = byId("mission-execution-actions").querySelector(`[data-problem="${activeProblem}"]`);
  if (actions) actions.hidden = experience;
  if (experience) {
    for (const {node} of p01ResultHomes) node.hidden = true;
    byId("case-results").hidden = true;
    byId("case-progress").hidden = true;
    byId("resource-operation").hidden = true;
  } else if (restore && missionResults.has(activeProblem)) {
    renderEnvelope(missionResults.get(activeProblem));
  }
}
byId("h23-experience-tab").addEventListener("click", () => selectModelCallPane("experience"));
byId("h23-grade-tab").addEventListener("click", () => selectModelCallPane("grade"));
byId("h23-chat-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (executionPending) return;
  setBusy(true, false);
  setText("h23-chat-status", "현재 코드로 Nova Lite에 질문을 보내고 있습니다.");
  setText("h23-chat-reply", ""); setText("h23-chat-meta", "");
  byId("h23-chat-details").hidden = true;
  try {
    const payload = await request("/api/practice/P23/chat", {message:byId("h23-chat-input").value});
    setText("h23-chat-reply", payload.reply);
    setText("h23-chat-status", "모델 답변을 받았습니다. 체험 결과는 미션 채점과 별개입니다.");
    setText("h23-chat-meta", `입력 ${payload.usage?.inputTokens ?? "—"} Token · 출력 ${payload.usage?.outputTokens ?? "—"} Token · ${payload.stop_reason === "max_tokens" ? "출력 한도에 도달했습니다. 답변이 중간에 끝날 수 있습니다." : "모델 응답 종료"}`);
    setText("h23-chat-raw", rawResponses.get(payload) ?? JSON.stringify(payload,null,2));
    byId("h23-chat-details").hidden = false;
  } catch (error) {
    setText("h23-chat-status", typeof error.detail === "string" ? error.detail : "질문 내용과 코드 적용 상태를 확인하세요.");
    setText("h23-chat-raw", JSON.stringify(error.detail || error.message,null,2));
    byId("h23-chat-details").hidden = false;
  } finally { setBusy(false, false); }
});

byId("mission-experience-run").addEventListener("click", async () => {
  if (executionPending) return;
  const problem = activeProblem;
  byId("mission-experience-summary").replaceChildren();
  setBusy(true, false);
  setText("mission-experience-status", "현재 기능을 실행하고 있습니다. 모델·검색·스캔은 시간이 걸릴 수 있습니다.");
  byId("mission-experience-details").hidden = true;
  try {
    const config=experienceCatalog[problem];
    if(!config)throw Error("미션 입력을 불러오지 못했습니다. 새로고침하세요.");
    const body=config.mode==="message" ? {message:byId("native-message").value,...(problem==="P09"?{stage:byId("native-stage").value}:{})} : config.mode==="scenario" ? {case_id:byId("native-scenario").value,...(config.editable?{message:byId("native-message").value}:{})} : config.mode==="operation" ? {operation:byId("native-scenario").value,message:byId("native-message").value} : undefined;
    const result = await request(`/api/experience/${problem}`,body);
    showExperienceSummary(result);
    setText("mission-experience-raw", rawResponses.get(result) ?? JSON.stringify(result, null, 2));
    setText("mission-experience-status", "응답을 받았습니다.");
  } catch (error) {
    setText("mission-experience-status", "실행이 끝나지 않았습니다. 코드 적용 상태와 아래 응답을 확인하세요.");
    setText("mission-experience-raw", JSON.stringify(error.detail || error.message, null, 2));
  } finally {
    byId("mission-experience-details").hidden = false;
    byId("mission-experience-details").open = false;
    setBusy(false, false);
  }
});


byId("document-upload-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (executionPending) return;
  const button = byId("document-upload-submit"); button.disabled = true;
  setBusy(true, false); setText("mission-experience-status", "입력한 문서를 업로드하고 있습니다…");
  byId("mission-experience-summary").replaceChildren();
  byId("mission-experience-details").hidden = true;
  try {
    const payload = await request("/api/documents/upload", {title: byId("document-upload-title").value, body: byId("document-upload-body").value});
    const run = payload.execution; const outcome = run?.execution?.execution_status;
    const calls = run?.execution?.calls || [];
    const finished = run?.lifecycle_status === "finished" && run?.closure?.state === "closed" && outcome === "returned" && ["store_source", "embed"].every(operation => calls.some(call => call.operation === operation && call.state === "complete"));
    setText("mission-experience-status", finished ? "문서 처리가 완료되었습니다. 아래에서 저장·임베딩 응답을 확인하세요." : outcome === "not_implemented" ? "문서 처리 함수를 구현하고 컨테이너에 적용하세요." : `문서 처리가 완료되지 않았습니다 (${outcome || run?.lifecycle_status || "응답 확인 필요"}). RAW 응답에서 실행 상태를 확인하세요.`);
    setText("mission-experience-raw", rawResponses.get(payload) ?? JSON.stringify(payload, null, 2));
    if (run?.execution?.result) {
      const pre = document.createElement("pre"); pre.textContent = JSON.stringify(run.execution.result, null, 2);
      byId("mission-experience-summary").append(pre);
    }
  } catch (error) {
    setText("mission-experience-status", "업로드가 완료되지 않았습니다. 문서 입력과 코드·AWS 자원 상태를 확인하세요.");
    setText("mission-experience-raw", JSON.stringify(error.detail || error.message, null, 2));
  } finally {
    byId("mission-experience-details").hidden = false;
    button.disabled = false; setBusy(false, false);
  }
});


function updateKnowledgeLinks(status) {
  const search = byId("knowledge-search-submit");
  const ready = status.state === "present" && status.search_ready === true;
  search.dataset.resourceReady = String(ready);
  search.disabled = !ready || executionPending;
  search.title = ready ? "입력한 검색어로 문서를 검색합니다" : "AWS 자원 준비 또는 상태 확인으로 검색 준비를 확인하세요";
  setText("knowledge-search-help", ready ? "검색 준비 완료. 검색어를 입력하고 검색하세요." : "AWS 자원을 준비하거나 상태를 확인하세요. 검색 준비가 완료되면 검색 버튼이 활성화됩니다.");
  const container = byId("knowledge-console-links");
  container.replaceChildren();
  const names = {"S3 source bucket":"S3 원문", "S3 vector bucket":"S3 벡터", "Vector index":"벡터 인덱스", "IAM role":"IAM 역할", "Knowledge Base":"Knowledge Base", "Data source":"Data source"};
  for (const [type, label] of Object.entries(names)) {
    const resource = status.resources?.find(item => item.type === type && item.state === "present");
    const valid = resource?.console_url?.startsWith("https://us-east-1.console.aws.amazon.com/");
    const control = document.createElement(valid ? "a" : "span");
    control.textContent = `${label} ↗`;
    control.title = valid ? `${resource.name}${resource.console_hint ? ` · ${resource.console_hint}` : ""}` : "자원 상태를 먼저 확인하세요";
    if (valid) { control.href = resource.console_url; control.target = "_blank"; control.rel = "noopener noreferrer"; }
    else { control.setAttribute("aria-disabled", "true"); control.tabIndex = 0; }
    container.append(control);
  }
}
updateKnowledgeLinks({resources: []});

function updateDocumentLinks(status) {
  const source = status.resources?.find(resource => resource.type === "S3 source bucket" && resource.state === "present");
  const bucket = source?.name;
  const s3 = byId("document-s3-link"); const titan = byId("document-titan-link");
  s3.disabled = !bucket;
  s3.dataset.url = bucket ? `https://us-east-1.console.aws.amazon.com/s3/buckets/${encodeURIComponent(bucket)}?region=us-east-1&prefix=h02%2Fknowledge%2F&showversions=false` : "";
  titan.disabled = !(status.state === "present" && (bucket || status.prepared));
  for (const button of [s3, titan]) button.parentElement.tabIndex = button.disabled ? 0 : -1;
  titan.dataset.url = titan.disabled ? "" : "https://us-east-1.console.aws.amazon.com/bedrock/home?region=us-east-1#/model-catalog";
  setText("document-console-help", bucket ? "S3에서 저장된 원문을 확인하세요. Titan은 모델 카탈로그에서 Amazon Titan Text Embeddings V2를 선택하세요." : "AWS 자원을 준비하거나 자원 상태를 확인하면 바로가기가 활성화됩니다.");
}
for (const id of ["document-s3-link", "document-titan-link"]) {
  byId(id).addEventListener("click", () => {
    const button = byId(id);
    if (!button.disabled && button.dataset.url) window.open(button.dataset.url, "_blank", "noopener,noreferrer");
  });
}

byId("knowledge-search-form").addEventListener("submit", async event => {
  event.preventDefault();
  if (activeProblem !== "P03" || executionPending || byId("knowledge-search-submit").dataset.resourceReady !== "true") return;
  const button = byId("knowledge-search-submit"); button.disabled = true;
  setBusy(true, false);
  byId("mission-experience-summary").replaceChildren();
  byId("mission-experience-details").hidden = true;
  setText("mission-experience-status", "입력한 검색어로 문서를 찾고 있습니다…");
  try {
    const payload = await request("/api/knowledge/search", {query: byId("knowledge-search-query").value});
    const run = payload.execution, worker = run?.execution, result = worker?.result;
    if (run?.lifecycle_status === "finished" && worker?.execution_status === "returned" && result?.status === "ready") {
      const hits = result.result?.results || [];
      setText("mission-experience-status", `검색 결과 ${hits.length}건을 찾았습니다.`);
      for (const [index, hit] of hits.entries()) {
        const card = document.createElement("section"); card.className = "case-card";
        const title = document.createElement("strong"); title.textContent = `검색 결과 ${index + 1}`;
        const content = document.createElement("p"); content.textContent = hit.content?.text || "본문 없음";
        const source = document.createElement("small"); source.textContent = `출처: ${hit.location?.s3Location?.uri || "출처 없음"} · 검색 점수: ${hit.score ?? "—"}`;
        card.append(title, content, source); byId("mission-experience-summary").append(card);
      }
    } else {
      setText("mission-experience-status", result?.status === "waiting" ? "문서 동기화가 진행 중입니다. 완료 후 다시 검색하세요." : worker?.execution_status === "not_implemented" ? "검색 함수를 구현하고 컨테이너에 적용하세요." : "검색을 완료하지 못했습니다. 코드 적용 상태와 RAW 응답을 확인하세요.");
    }
    setText("mission-experience-raw", rawResponses.get(payload) ?? JSON.stringify(payload, null, 2));
  } catch (error) {
    setText("mission-experience-status", typeof error.detail === "string" ? error.detail : "검색 실행 상태를 확인하세요.");
    setText("mission-experience-raw", JSON.stringify(error.detail || error.message, null, 2));
  } finally {
    byId("mission-experience-details").hidden = false;
    byId("mission-experience-details").open = false;
    button.disabled = button.dataset.resourceReady !== "true"; setBusy(false, false);
  }
});

function updateGuardrailChat(status) {
  const button = byId("guardrail-chat-submit");
  const ready = status.state === "present" && status.model_ready === true;
  button.dataset.resourceReady = String(ready);
  button.disabled = !ready || executionPending;
  button.title = ready ? "현재 함수로 모델을 호출합니다" : "AWS Guardrail을 준비하거나 상태를 확인하세요";
  setText("guardrail-chat-help", ready ? "Guardrail 준비 완료. 입력한 문장으로 실제 모델 답변을 확인하세요." : "AWS Guardrail을 준비하거나 상태를 확인하세요. 준비 완료 후 요청 버튼이 활성화됩니다.");
}
updateGuardrailChat({});
byId("guardrail-chat-form").addEventListener("submit", async event => {
  event.preventDefault();
  const button = byId("guardrail-chat-submit");
  if (activeProblem !== "P04" || executionPending || button.dataset.resourceReady !== "true") return;
  setBusy(true, false);
  byId("mission-experience-summary").replaceChildren();
  byId("mission-experience-details").hidden = true;
  setText("mission-experience-status", "Guardrail을 연결한 모델 답변을 기다리고 있습니다…");
  try {
    const payload = await request("/api/practice/P04/chat", {message:byId("guardrail-chat-message").value});
    const execution = payload.execution, worker = execution?.execution, response = worker?.result;
    if (execution?.lifecycle_status === "finished" && worker?.execution_status === "returned" && response?.output) {
      const reply = (response.output.message?.content || []).map(item=>item.text || "").join("");
      setText("mission-experience-status", "정책이 적용된 모델 응답을 받았습니다.");
      const card = document.createElement("article"); card.className = "model-response-card";
      const head = document.createElement("header"); head.className = "model-response-head";
      const avatar = document.createElement("span"); avatar.className = "model-response-avatar"; avatar.textContent = "AI"; avatar.setAttribute("aria-hidden", "true");
      const label = document.createElement("strong"); label.textContent = "모델 답변";
      head.append(avatar, label);
      const answer = document.createElement("div"); answer.className = "model-response-body";
      reply.split(/(\{EMAIL\})/g).forEach(part => {
        if (part === "{EMAIL}") { const mark = document.createElement("mark"); mark.textContent = part; answer.append(mark); }
        else answer.append(document.createTextNode(part));
      });
      const policyRow = document.createElement("div"); policyRow.className = "model-response-policies";
      const trace = response.trace?.guardrail;
      for (const assessments of Object.values(trace?.outputAssessments || {})) {
        for (const item of assessments.flatMap(assessment=>assessment.sensitiveInformationPolicy?.piiEntities || [])) {
          const badge = document.createElement("span"); badge.className = "model-response-policy";
          badge.textContent = item.type === "EMAIL" && item.action === "ANONYMIZED" ? "이메일 비식별화" : `${item.type}: ${item.action}`;
          policyRow.append(badge);
        }
      }
      const metadata = document.createElement("footer"); metadata.className = "model-response-meta";
      const stopLabels = {guardrail_intervened:"Guardrail이 출력을 처리했습니다", end_turn:"답변 완료", max_tokens:"출력 한도 도달"};
      for (const text of [stopLabels[response.stopReason] || response.stopReason || "종료 정보 없음", `입력 ${response.usage?.inputTokens ?? "—"} Token`, `출력 ${response.usage?.outputTokens ?? "—"} Token`]) {
        const item = document.createElement("span"); item.textContent = text; metadata.append(item);
      }
      card.append(head, answer); if (policyRow.children.length) card.append(policyRow); card.append(metadata);
      byId("mission-experience-summary").append(card);
      if (trace) {
        const policy = document.createElement("details"), title = document.createElement("summary"), content = document.createElement("pre");
        policy.className = "model-response-details";
        title.textContent = "Guardrail 정책 적용 내역";
        const stop = document.createElement("p"); stop.textContent = `응답 종료: ${response.stopReason || "—"}`;
        content.textContent = JSON.stringify(trace, null, 2);
        policy.append(title,stop,content); byId("mission-experience-summary").append(policy);
      }
    } else {
      setText("mission-experience-status", worker?.execution_status === "not_implemented" ? "모델 호출 미실행 — 함수를 구현하고 컨테이너에 적용하세요." : "모델 응답을 받지 못했습니다. 직접 테스트 RAW 응답에서 실행 오류를 확인하세요.");
    }
    setText("mission-experience-raw", rawResponses.get(payload) ?? JSON.stringify(payload,null,2));
  } catch (error) {
    setText("mission-experience-status", typeof error.detail === "string" ? error.detail : "모델 응답을 받지 못했습니다.");
    setText("mission-experience-raw", JSON.stringify(error.detail || error.message,null,2));
  } finally {
    byId("mission-experience-details").hidden = false;
    byId("mission-experience-details").open = false;
    setBusy(false,false);
  }
});
