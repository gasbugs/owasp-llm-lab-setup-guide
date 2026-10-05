const RedTeamTarget = require('./redteam-target.cjs');
class FullScanTarget extends RedTeamTarget {
  constructor() { super(); this.remaining = 0; this.expiresAt = 0; }
  id() { return 'application-full-scan-jwt'; }
  async callApi(prompt) {
    // 두 요청 묶음이 끝나거나 다음 요청의 시간 여유가 없으면 먼저 로그인한다.
    if (this.remaining === 0 || Date.now() + 60000 >= this.expiresAt) {
      const response = await fetch('http://llm-security-application-gateway:8000/.well-known/login', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ username: 'public-reader', password: 'public-reader-demo' }),
        signal: AbortSignal.timeout(10000),
      });
      if (!response.ok) return { error: `Login HTTP ${response.status}` };
      const login = await response.json();
      if (!login.access_token || !Number.isFinite(login.expires_in) || login.expires_in <= 60)
        return { error: 'Login returned no usable Token lifetime' };
      // Token은 메모리에만 두고 원래 provider의 인증된 Application 호출을 재사용한다.
      process.env.CONTROL_PLANE_ACCESS_TOKEN = login.access_token;
      this.expiresAt = Date.now() + login.expires_in * 1000;
      this.remaining = 2;
    }
    this.remaining -= 1;
    // 실패한 공격을 재전송하지 않는다. 원시 응답 저장도 기존 provider가 담당한다.
    return super.callApi(prompt);
  }
}
module.exports = FullScanTarget;
