# LLMGoat를 한 줄로 로컬 Build·배포하기

이 예제는 기존 `docker/llmgoat/Dockerfile`과 통합 실습용 Compose를 바꾸지 않는다.
별도 image·container·volume을 만들고, 기존 5000번 대신 15000번 포트를 사용한다.

`Containerfile`은 확인한 LLMGoat `v0.1.0` GPU image를 고정해서 가져온다. 같은
버전의 전체 소스와 GPL 원문도 image 안에 넣는다. `compose.yaml`은 이 image를
Build하고 GPU, 포트, 모델 저장 volume을 연결한다.

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

## 한 줄로 Build하고 배포하기

이 디렉터리에서 다음 한 줄을 실행한다. `--build`는 로컬 image를 만들고, `-d`는
완성된 container를 백그라운드에서 시작한다. image를 registry에 push하지 않는다.

```bash
docker compose up -d --build
```

첫 Build에는 CUDA가 들어 있는 GPU base image 수 GB를 내려받는다. 첫 실행에는
Gemma 2 GGUF model 약 5GB와 이미지 문제에 사용하는 Salesforce BLIP model도
별도로 내려받으므로 시간이 걸린다. 파일은 이후 Docker cache와 전용 volume에서
재사용한다. Gemma model은 LLMGoat 소스의 GPL과 별도로 Google Gemma 이용
조건이 적용된다.

## 실행 결과 확인

`STATUS`가 처음에는 `health: starting`일 수 있다. model 다운로드와 로딩이 끝나면
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
