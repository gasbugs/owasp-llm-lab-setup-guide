# LLMGoat local training image notice

- Upstream project: SECFORCE/LLMGoat
- Upstream version: v0.1.0
- Upstream commit: `9388bd2c1a629f3bd56be56140d3aae97d01e6cf`
- Source: <https://github.com/SECFORCE/LLMGoat/tree/v0.1.0>
- License: GNU General Public License v3.0

이 Build는 upstream challenge 코드를 수정하지 않는다. setup 저장소의
`proxy_entrypoint.py`만 통합 포털의 `/llmgoat` 경로를 연결한다. 실행 중 별도로
내려받는 Gemma model에는 Google의 Gemma 이용 조건이 적용되므로 LLMGoat의
GPL과 구분해 확인해야 한다.
