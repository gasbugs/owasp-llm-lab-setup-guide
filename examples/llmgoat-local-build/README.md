# LLMGoat를 로컬 Build한 뒤 실행하기

이 예제는 기존 `docker/llmgoat/Dockerfile`과 통합 실습용 Compose를 바꾸지 않는다.
별도 image·container·volume을 만들고, 기존 5000번 대신 15000번 포트를 사용한다.

`Containerfile`은 SECFORCE가 게시한 GPU image를 원본 registry에서 digest로 직접
받고, `gasbugs/LLMGoat` 포크의 `v0.1.0` 전체 소스와 GPL 원문을 image 안에 넣는다.
원본 image가 사라졌을 때만 `Containerfile.source-build`가 NVIDIA CUDA image와
같은 포크 소스로 GPU 실행 파일을 로컬에서 다시 만든다. `compose.yaml`은 선택한
Containerfile로 image를 Build하고 GPU, 포트, 모델 저장 volume을 연결한다.

LLMGoat `v0.1.0`은 Ollama API를 호출하지 않는다. 애플리케이션 안의
`llama-cpp-python`이 `gemma-2-9b-it-Q4_K_M.gguf`를 직접 불러오는 구조다. 따라서
별도 Ollama 서비스를 추가하지 않고 이 원래 구조를 유지한다. 그래야 upstream
챌린지 코드와 이미 확인한 응답 경로를 바꾸지 않는다.

## 준비 상태 확인

Docker Engine, Docker Compose v2, NVIDIA Container Toolkit이 설치된 GPU 환경에서
실행한다. EC2에서 접속한다면 보안 그룹은 15000번 포트를 수강생 본인의 공인
IPv4 `/32`에만 허용하고 `0.0.0.0/0`에는 열지 않는다. LLMGoat는 의도적으로
취약한 애플리케이션이다.

```bash
docker compose version
nvidia-smi
```

두 명령이 각각 Compose 버전과 GPU 정보를 표시하면 다음 단계로 진행한다.

## Image Build하기

이 디렉터리에서 먼저 image를 만든다. 이 단계는 Containerfile과 대응 소스·GPL
원문을 image에 넣지만, 약 5GB의 Gemma model은 아직 내려받지 않는다.

```bash
docker compose build
```

첫 Build에는 CUDA가 들어 있는 고정 GPU base image 수 GB를 내려받는다. 완료되면
`localhost/llmgoat-local-build:v0.1.0` image가 로컬에 생긴다. Compose의
`pull_policy: never`는 다음 실행에서 Registry image 대신 이 로컬 image만 쓰게
한다.

SECFORCE image가 실제로 없어졌다는 오류가 확인된 경우에만 포크 소스 Build를
선택한다. CUDA용 `llama-cpp-python`을 컴파일하므로 이 경로는 더 오래 걸린다.

```bash
LLMGOAT_DOCKERFILE=Containerfile.source-build docker compose build
```

## Container 실행하기

Build한 image로 container를 백그라운드에서 실행한다.

```bash
docker compose up -d
```

첫 실행에는 LLMGoat가 Gemma 2 GGUF model 약 5GB를 Hugging Face에서 내려받아
`llmgoat-local-models` volume에 저장한다. 이미지 문제에 사용하는 Salesforce
BLIP model도 `llmgoat-local-cache` volume에 저장한다. 두 volume은 image를 다시
Build하거나 container를 다시 만들어도 유지되므로 다음 실행에서는 같은 파일을
재사용한다. Gemma model에는 LLMGoat 소스의 GPL과 별도로 Google Gemma 이용
조건이 적용된다.

## 실행 결과 확인

`STATUS`가 처음에는 `health: starting`일 수 있다. 이때는 웹 서버가 고장 난 것이
아니라 Gemma를 내려받거나 GPU에 올리는 중이다. 다운로드와 로딩이 끝나면
`healthy`로 바뀐다.

```bash
docker compose ps
docker compose logs -f llmgoat
```

로그 확인은 `Ctrl+C`로 빠져나온다. container는 계속 실행된다. 로컬 PC에서는
`http://127.0.0.1:15000`, EC2에서는 `http://<EC2_PUBLIC_IP>:15000`으로 접속한다.

다음 요청이 JSON을 반환하면 웹 서버와 model 상태 endpoint까지 연결된 것이다.

```bash
curl -sS http://127.0.0.1:15000/api/model_status
```

출력 예시:

```json
{"model_busy":false}
```

`model_busy`가 `false`이면 model 다운로드와 로딩이 끝났고 새 요청을 받을 수
있다는 뜻이다. `true`이면 앞 요청을 처리 중이므로 끝난 뒤 다시 확인한다.

## 소스와 라이선스 확인

실행 파일에 대응하는 전체 소스, GPL 원문, 이 image의 안내문이 들어 있는지
확인한다.

```bash
docker compose exec llmgoat sh -lc \
  'ls /usr/src/llmgoat-v0.1.0 && sed -n "1,8p" /app/LICENSE && cat /usr/share/doc/llmgoat/NOTICE.md'
```

`llmgoat`, `Dockerfile.gpu`, `LICENSE` 등이 보이면 소스 묶음이 들어간 것이다.
이어지는 `GNU GENERAL PUBLIC LICENSE`는 라이선스 원문이고, 마지막 안내문은
upstream 버전과 별도 Gemma 조건을 구분한다.

## 중지하기

container와 network만 내리고 내려받은 model과 cache는 남긴다.

```bash
docker compose down
```

model까지 다시 내려받고 싶은 경우에만 `docker compose down -v`를 사용한다.
`-v`를 붙이면 이 예제의 model·cache volume이 삭제되어 복구할 수 없다.
