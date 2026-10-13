import { createHash, timingSafeEqual } from "node:crypto";
import { spawn } from "node:child_process";
import { createServer } from "node:http";
import { readFile } from "node:fs/promises";

const controlToken = process.env.GUIDED_CONTROL_LAB13_TOKEN;
const verifierToken = process.env.GUIDED_VERIFIER_LAB13_TOKEN;
const uuidPattern = /^[0-9a-f-]{36}$/;
const equal = (left, right) => {
  const a = Buffer.from(left || "");
  const b = Buffer.from(right || "");
  return a.length === b.length && timingSafeEqual(a, b);
};
const bearer = (request, expected) => equal(request.headers.authorization, `Bearer ${expected}`);
const digest = (value) => createHash("sha256").update(value).digest("hex");
async function scaffoldDigest() {
  const hash = createHash("sha256");
  for (const path of ["Containerfile", "server.mjs", "transform.cjs"]) {
    hash.update(path);
    hash.update(await readFile(`/work/${path}`));
  }
  return hash.digest("hex");
}

async function body(request) {
  const chunks = [];
  for await (const chunk of request) chunks.push(chunk);
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function runPromptfoo(suiteId, description = null) {
  return new Promise((resolve) => {
    const output = `/state/${suiteId}.json`;
    const child = spawn("promptfoo", ["eval", "--config", "/work/promptfooconfig.yaml", "--output", output, "--no-cache", ...(description ? ["--filter-pattern", `^${description}$`] : [])], {
      env: process.env,
      cwd: "/work",
      stdio: ["ignore", "pipe", "pipe"],
      timeout: 90000,
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    child.on("close", (code) => resolve({ code, stdout: stdout.slice(-8000), stderr: stderr.slice(-8000), output }));
  });
}

const caseNames = ["H13-NORMAL — 정상 요청은 Main 경로를 유지한다", "H13-RISK — 위험 요청은 Main 전에 멈춘다"];
let caseBusy = false;
async function readPrefix(suite) {
  try { return JSON.parse(await readFile(`/state/${suite}.prefix.json`, "utf8")); }
  catch (error) { if (error.code === "ENOENT") return null; throw error; }
}
async function runCase(input) {
  if (Object.keys(input).sort().join(",") !== "case_id,started_at,suite_id" ||
      !uuidPattern.test(input.suite_id || "") || !caseNames.includes(input.case_id) ||
      !Number.isFinite(Date.parse(input.started_at)) || Math.abs(Date.now()-Date.parse(input.started_at)) > 900000)
    throw Object.assign(new Error("invalid fixed case execution"), {status:422});
  if (caseBusy) throw Object.assign(new Error("another case is running"), {status:409});
  caseBusy = true;
  try {
    const configDigest = digest(await readFile("/work/promptfooconfig.yaml"));
    const scaffold = await scaffoldDigest();
    let prefix = await readPrefix(input.suite_id);
    if (!prefix) prefix = {suite_id:input.suite_id, started_at:input.started_at, config_digest:configDigest,
                          scaffold_digest:scaffold, entries:[], state:"paused"};
    if (prefix.state !== "paused" || prefix.started_at !== input.started_at ||
        prefix.config_digest !== configDigest || prefix.scaffold_digest !== scaffold ||
        prefix.entries.some((entry,i)=>entry.case_id !== caseNames[i]) ||
        caseNames[prefix.entries.length] !== input.case_id)
      throw Object.assign(new Error("suite cannot advance"), {status:409});
    prefix.state = "running";
    await writeReceipt(`/state/${input.suite_id}.prefix.json`, JSON.stringify(prefix));
    const child = `${input.suite_id}-${prefix.entries.length}`;
    const result = await runPromptfoo(child, input.case_id);
    const raw = await readFile(result.output, "utf8");
    if (digest(await readFile("/work/promptfooconfig.yaml")) !== configDigest || await scaffoldDigest() !== scaffold)
      throw new Error("execution source changed");
    const entry = {case_id:input.case_id, child, observed_at:new Date().toISOString(),
                   exit_code:result.code, artifact_digest:digest(raw)};
    prefix.entries.push(entry);
    prefix.state = prefix.entries.length === caseNames.length ? "finished" : "paused";
    await writeReceipt(`/state/${input.suite_id}.prefix.json`, JSON.stringify(prefix));
    return {suite_id:input.suite_id, case_id:input.case_id, state:prefix.state};
  } finally { caseBusy = false; }
}

const server = createServer(async (request, response) => {
  try {
    if (request.method === "GET" && ["/livez", "/readyz"].includes(request.url)) {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ status: "ready", tool: "promptfoo", version: "0.121.20" }));
      return;
    }
    if (request.method === "POST" && request.url === "/v1/run-case") {
      if (!bearer(request, controlToken)) throw Object.assign(new Error("unauthorized"), {status:401});
      const value = await runCase(await body(request));
      response.writeHead(200, {"Content-Type":"application/json"}); response.end(JSON.stringify(value)); return;
    }
    const prefixMatch = request.url?.match(/^\/v1\/case-artifacts\/([0-9a-f-]{36})$/);
    if (request.method === "GET" && prefixMatch) {
      if (!bearer(request, verifierToken)) throw Object.assign(new Error("unauthorized"), {status:401});
      const prefix = await readPrefix(prefixMatch[1]);
      if (!prefix) throw Object.assign(new Error("suite not found"), {status:404});
      const entries = [];
      for (const entry of prefix.entries) entries.push({...entry, artifact_raw:await readFile(`/state/${entry.child}.json`, "utf8")});
      response.writeHead(200, {"Content-Type":"application/json"}); response.end(JSON.stringify({...prefix, entries, current_config_digest:digest(await readFile("/work/promptfooconfig.yaml")), current_scaffold_digest:await scaffoldDigest()})); return;
    }
    if (request.method === "POST" && request.url === "/v1/run") {
      if (!bearer(request, controlToken)) throw Object.assign(new Error("unauthorized"), { status: 401 });
      const input = await body(request);
      if (!uuidPattern.test(input.suite_id || "")) throw Object.assign(new Error("invalid suite"), { status: 422 });
      const result = await runPromptfoo(input.suite_id);
      const artifact = await readFile(result.output);
      const receipt = {
        suite_id: input.suite_id,
        started_at: input.started_at,
        observed_at: new Date().toISOString(),
        tool: "promptfoo",
        tool_version: "0.121.20",
        exit_code: result.code,
        artifact_digest: digest(artifact),
        config_digest: digest(await readFile("/work/promptfooconfig.yaml")),
        scaffold_digest: await scaffoldDigest(),
        stdout_tail: result.stdout,
        stderr_tail: result.stderr,
      };
      await writeReceipt(`${result.output}.receipt.json`, JSON.stringify(receipt));
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ suite_id: input.suite_id, exit_code: result.code, artifact_digest: receipt.artifact_digest }));
      return;
    }
    const match = request.url?.match(/^\/v1\/artifacts\/([0-9a-f-]{36})$/);
    if (request.method === "GET" && match) {
      if (!bearer(request, verifierToken)) throw Object.assign(new Error("unauthorized"), { status: 401 });
      const artifact = JSON.parse(await readFile(`/state/${match[1]}.json`, "utf8"));
      const receipt = JSON.parse(await readFile(`/state/${match[1]}.json.receipt.json`, "utf8"));
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ receipt, artifact }));
      return;
    }
    response.writeHead(404).end();
  } catch (error) {
    response.writeHead(error.status || 500, { "Content-Type": "application/json" });
    response.end(JSON.stringify({ detail: error.message }));
  }
});

async function writeReceipt(path, data) {
  const { writeFile } = await import("node:fs/promises");
  await writeFile(path, data, { mode: 0o600 });
}

server.listen(8000, "0.0.0.0");
