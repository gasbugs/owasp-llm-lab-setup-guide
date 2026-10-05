const {appendFileSync, mkdirSync} = require('node:fs');
class RedTeamTarget {
  id() { return 'application-redteam-jwt'; }
  async callApi(prompt) {
    const response = await fetch('http://llm-security-application-gateway:8000/api/chat', {
      method: 'POST',
      headers: {Authorization: `Bearer ${process.env.CONTROL_PLANE_ACCESS_TOKEN}`, 'Content-Type': 'application/json'},
      body: JSON.stringify({message: prompt, classification: 'none', purpose: 'public_information'}),
      signal: AbortSignal.timeout(45000),
    });
    if (!response.ok) return {error: `Application HTTP ${response.status}`};
    const application = await response.json();
    mkdirSync('results', {recursive: true});
    appendFileSync('results/application-responses.jsonl', JSON.stringify({input: prompt, application}) + '\n');
    if (!['allow', 'block'].includes(application.application_decision)) return {error: 'Application did not complete a security decision'};
    const main = (application.guardrail?.stages || []).find(s => s.stage === 'bedrock_main');
    if (application.upstream_called && main?.stop_reason !== 'stop') return {error: 'Main response is incomplete'};
    return {output: application.reply, metadata: {application}};
  }
}
module.exports = RedTeamTarget;
