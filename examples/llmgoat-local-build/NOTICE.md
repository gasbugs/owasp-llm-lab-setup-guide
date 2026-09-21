# LLMGoat local training image notice

- Upstream project: SECFORCE/LLMGoat
- Upstream version: v0.1.0
- Upstream commit: `9388bd2c1a629f3bd56be56140d3aae97d01e6cf`
- Source: <https://github.com/SECFORCE/LLMGoat/tree/v0.1.0>
- License: GNU General Public License v3.0

이 로컬 Build는 LLMGoat 애플리케이션 코드를 수정하지 않는다. 확인한 upstream
GPU image를 digest로 고정하고, 대응하는 전체 소스와 GPL 원문을 같은 image 안에
추가한다. 실행 중 별도로 내려받는 Gemma model에는 Google의 Gemma 이용 조건이
적용되므로 LLMGoat의 GPL과 구분해 확인해야 한다.
