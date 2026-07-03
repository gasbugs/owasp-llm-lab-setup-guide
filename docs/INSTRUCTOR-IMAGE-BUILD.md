# Instructor Image Build

이 문서는 강사 또는 운영자가 실습 컨테이너 이미지를 빌드하고 Docker Hub에 push하는 절차입니다.

## 사전 조건

- Podman
- Docker Hub 계정
- `podman login docker.io`
- Linux/amd64 이미지 빌드를 위한 Podman machine 또는 x86_64 Linux 환경

## 빌드 대상

| 이미지 | Dockerfile |
|---|---|
| `owasp-llm-base-gpu` | `docker/base-gpu/Dockerfile` |
| `owasp-llm-vuln-rag` | `docker/vuln-rag/Dockerfile` |
| `owasp-llm-vuln-agent` | `docker/vuln-agent/Dockerfile` |
| `owasp-llm-llmgoat` | `docker/llmgoat/Dockerfile` |
| `owasp-llm-dvla` | `docker/dvla/Dockerfile` |

## 빌드와 push

```bash
cd docker
DOCKERHUB_NAMESPACE=your-dockerhub-id TAG=latest ./build-and-push.sh
```

## EC2에서 pull 확인

SSM 접속 후:

```bash
sudo -u ubuntu podman pull docker.io/your-dockerhub-id/owasp-llm-vuln-rag:latest
sudo -u ubuntu podman images | grep owasp-llm
```

## 주의

- 이미지는 의도적으로 취약한 실습 앱입니다.
- public registry에 올릴 경우 이미지 설명에 교육용 취약 앱임을 명시하세요.
- 강의 중 사용하는 namespace와 `user-data.sh.tpl`의 image URL이 일치해야 합니다.

