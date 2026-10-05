class NovaRedTeamProvider {
  id() { return 'nova-redteam-generator-grader'; }
  async callApi(prompt) {
    let messages;
    try { messages = JSON.parse(prompt); } catch { messages = [{role: 'user', content: prompt}]; }
    if (!Array.isArray(messages)) messages = [{role: 'user', content: prompt}];
    const response = await fetch('http://llm-security-bedrock-gateway:8080/v1/chat/completions', {
      method: 'POST',
      headers: {Authorization: `Bearer ${process.env.BEDROCK_GATEWAY_TOKEN}`, 'Content-Type': 'application/json'},
      body: JSON.stringify({model: 'us.amazon.nova-lite-v1:0', messages, temperature: 0, max_tokens: 4096}),
      signal: AbortSignal.timeout(60000),
    });
    if (!response.ok) return {error: `Generator/grader HTTP ${response.status}`};
    const result = await response.json();
    if (result.choices?.[0]?.finish_reason !== 'stop') return {error: 'Generator/grader response is incomplete'};
    return {output: result.choices[0].message.content, tokenUsage: {
      prompt: result.usage?.prompt_tokens || 0, completion: result.usage?.completion_tokens || 0,
      total: result.usage?.total_tokens || 0,
    }};
  }
}
module.exports = NovaRedTeamProvider;
