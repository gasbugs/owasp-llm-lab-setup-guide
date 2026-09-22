# LLMGoat local training image notice

- Upstream project: SECFORCE/LLMGoat
- Upstream version: v0.1.0
- Upstream commit: `9388bd2c1a629f3bd56be56140d3aae97d01e6cf`
- Installation source fork: <https://github.com/gasbugs/LLMGoat/tree/v0.1.0>
- Original source: <https://github.com/SECFORCE/LLMGoat/tree/v0.1.0>
- Normal runtime image: `ghcr.io/secforce/llmgoat-gpu:v0.1.0`
- Source-build fallback base: `nvidia/cuda:12.2.2-devel-ubuntu22.04`
- LLMGoat and course wrapper license: GNU General Public License v3.0 only

이 Build는 upstream challenge 코드를 수정하지 않는다. setup 저장소의
`proxy_entrypoint.py`만 통합 포털의 `/llmgoat` 경로를 연결하며 이 wrapper도
`GPL-3.0-only`로 제공한다. 기본 Build는 SECFORCE image를 직접 받고, 해당 image를
받을 수 없을 때만 NVIDIA CUDA image와 공개 포크 소스로 로컬에서 다시 만든다.
실행 중 별도로
내려받는 Gemma model에는 Google의 Gemma 이용 조건이 적용되므로 LLMGoat의
GPL과 구분해 확인해야 한다.
