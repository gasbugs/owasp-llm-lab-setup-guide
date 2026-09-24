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

function runPromptfoo(suiteId) {
  return new Promise((resolve) => {
    const output = `/state/${suiteId}.json`;
    const child = spawn("promptfoo", ["eval", "--config", "/work/promptfooconfig.yaml", "--output", output, "--no-cache"], {
      env: process.env,
      cwd: "/work",
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    child.stdout.on("data", (chunk) => { stdout += chunk.toString(); });
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    child.on("close", (code) => resolve({ code, stdout: stdout.slice(-8000), stderr: stderr.slice(-8000), output }));
  });
}

const server = createServer(async (request, response) => {
  try {
    if (request.method === "GET" && ["/livez", "/readyz"].includes(request.url)) {
      response.writeHead(200, { "Content-Type": "application/json" });
      response.end(JSON.stringify({ status: "ready", tool: "promptfoo", version: "0.121.20" }));
      return;
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
