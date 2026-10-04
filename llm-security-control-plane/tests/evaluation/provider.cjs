class ApplicationProvider {
  id() { return 'application-jwt'; }
  async callApi(prompt) {
    const response = await fetch('http://llm-security-application-gateway:8000/api/chat', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${process.env.CONTROL_PLANE_ACCESS_TOKEN}`,
        'Content-Type': 'application/json',
      },
      body: JSON.stringify({message: prompt, classification: 'none', purpose: 'public_information'}),
      signal: AbortSignal.timeout(120000),
    });
    if (!response.ok) return {error: `Application HTTP ${response.status}`};
    return {output: JSON.stringify(await response.json())};
  }
}
module.exports = ApplicationProvider;
