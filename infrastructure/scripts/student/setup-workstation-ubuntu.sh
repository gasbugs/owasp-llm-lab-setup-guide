#!/bin/bash
# ==============================================================================
# OWASP Top 10 for LLM Ubuntu 워크스테이션 준비 스크립트
# (Terraform, Docker, AWS CLI, Node.js/npm, agy)
#
# 이 스크립트는 Terraform을 실행하는 로컬 Ubuntu PC용입니다. 실제 EC2 실습
# 런타임은 install-lab.sh가 Docker Compose로 별도 구성합니다.
# - 오류 발생 시에도 멈추지 않고 후속 단계 계속 진행 (Fault-Tolerant)
# - npm 및 agy 환경변수(PATH) 자동 감지 및 보정 기능 내장
# - 비대화형 서브셸 환경 및 영구 환경설정(.bashrc, .profile) 완벽 지원
# - 실행 완료 후 상세 설치 결과 및 버전 통계 리포트 출력
# ==============================================================================

if [ "$(uname -s)" != "Linux" ] || [ ! -f /etc/os-release ]; then
    echo "이 스크립트는 Ubuntu Linux에서만 실행할 수 있습니다." >&2
    exit 1
fi

. /etc/os-release
if [ "${ID:-}" != "ubuntu" ]; then
    echo "지원하지 않는 배포판입니다: ${PRETTY_NAME:-unknown}. Ubuntu에서 실행하세요." >&2
    exit 1
fi

# 색상 정의
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# 단계별 결과 추적 배열
declare -a STEP_NAMES=()
declare -a STEP_STATUSES=()
declare -a STEP_NOTES=()

record_step() {
    local name="$1"
    local status="$2" # SUCCESS, WARNING, FAILED
    local note="$3"
    STEP_NAMES+=("$name")
    STEP_STATUSES+=("$status")
    STEP_NOTES+=("$note")
}

# ------------------------------------------------------------------------------
# 환경변수(PATH) 보정 헬퍼 함수
# ------------------------------------------------------------------------------
sync_environment_paths() {
    local candidate_dirs=(
        "$HOME/.npm-global/bin"
        "$HOME/.local/bin"
        "$HOME/.antigravity/bin"
        "$HOME/.gemini/antigravity-cli/bin"
        "$HOME/.terraform.d/bin"
        "/usr/local/bin"
        "/usr/bin"
        "/bin"
    )

    for dir in "${candidate_dirs[@]}"; do
        if [ -d "$dir" ]; then
            case ":$PATH:" in
                *":$dir:"*) ;; # 이미 PATH에 포함되어 있음
                *) export PATH="$dir:$PATH" ;;
            esac
        fi
    done
}

persist_path_entry() {
    local entry="$1"
    local pattern="$2"
    local files=("$HOME/.bashrc" "$HOME/.profile")

    for f in "${files[@]}"; do
        if [ -f "$f" ]; then
            if ! grep -Fq "$pattern" "$f" 2>/dev/null; then
                echo "$entry" >> "$f"
            fi
        fi
    done
}

# 스크립트 시작 시 기본 PATH 동기화
sync_environment_paths

echo -e "${BOLD}${CYAN}======================================================${NC}"
echo -e "${BOLD}${CYAN}   개발 및 인프라 자동화 도구 통합 설치 스크립트   ${NC}"
echo -e "${BOLD}${CYAN}======================================================${NC}"
echo "시작 시각: $(date '+%Y-%m-%d %H:%M:%S')"
echo ""

# ==============================================================================
# 1. Docker 설치
# ==============================================================================
echo -e "${BOLD}${BLUE}=============================="
echo -e " 1. Docker 설치"
echo -e "==============================${NC}"

DOCKER_SUCCESS=false
APT_TIMEOUT_OPTIONS=(
    -o Acquire::http::Timeout=20
    -o Acquire::https::Timeout=20
    -o Acquire::Retries=1
    -o DPkg::Lock::Timeout=30
)

docker_cli_ready() {
    command -v docker >/dev/null 2>&1 &&
        docker --version >/dev/null 2>&1 &&
        docker compose version >/dev/null 2>&1
}

install_docker_from_official_repository() {
    local docker_key_file
    local official_started
    local remaining_seconds
    docker_key_file="$(mktemp)"
    official_started="$(date +%s)"

    echo "Docker 공식 저장소 설치를 최대 60초 동안 시도합니다."
    if ! curl -fsSL --connect-timeout 5 --max-time 15 --retry 1 \
        https://download.docker.com/linux/ubuntu/gpg -o "$docker_key_file"; then
        rm -f "$docker_key_file"
        return 1
    fi

    if ! sudo install -m 0755 -d /etc/apt/keyrings ||
        ! sudo install -m 0644 "$docker_key_file" /etc/apt/keyrings/docker.asc; then
        rm -f "$docker_key_file"
        return 1
    fi
    rm -f "$docker_key_file"

    # 예전 설정을 교체해 서로 다른 Signed-By 경로가 충돌하지 않게 한다.
    sudo rm -f /etc/apt/sources.list.d/docker.list /etc/apt/sources.list.d/docker.sources
    echo \
      "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu \
      ${UBUNTU_CODENAME:-$VERSION_CODENAME} stable" | \
      sudo tee /etc/apt/sources.list.d/docker.list >/dev/null

    remaining_seconds=$((60 - $(date +%s) + official_started))
    if [ "$remaining_seconds" -le 0 ] ||
        ! sudo timeout "${remaining_seconds}s" apt-get \
            "${APT_TIMEOUT_OPTIONS[@]}" update >/dev/null 2>&1; then
        return 1
    fi

    remaining_seconds=$((60 - $(date +%s) + official_started))
    [ "$remaining_seconds" -gt 0 ] &&
        sudo timeout "${remaining_seconds}s" apt-get "${APT_TIMEOUT_OPTIONS[@]}" install -y \
            docker-ce docker-ce-cli containerd.io docker-buildx-plugin \
            docker-compose-plugin >/dev/null 2>&1
}

install_docker_from_ubuntu_repository() {
    echo "공식 설치가 실패해 Ubuntu 저장소의 docker.io로 전환합니다."

    # 실패한 외부 저장소를 제거해야 다음 apt-get update가 같은 주소에서 다시 멈추지 않는다.
    sudo rm -f /etc/apt/sources.list.d/docker.list /etc/apt/sources.list.d/docker.sources
    if sudo timeout 60s apt-get -o Acquire::ForceIPv4=true \
        "${APT_TIMEOUT_OPTIONS[@]}" update >/dev/null 2>&1; then
        sudo timeout 300s apt-get -o Acquire::ForceIPv4=true \
            "${APT_TIMEOUT_OPTIONS[@]}" install -y \
                docker.io docker-compose-v2 >/dev/null 2>&1
        return
    fi

    # AWS 지역 미러가 응답하지 않을 때 사용자가 실측한 Kakao Ubuntu 미러로 한 번만 우회한다.
    # Ubuntu 24.04의 deb822 파일과 이전 형식 sources.list가 있을 때만 정확한 공식 URL을 바꾼다.
    echo "Ubuntu 기본 미러가 응답하지 않아 Kakao 미러로 한 번 더 시도합니다."
    local source_file
    for source_file in /etc/apt/sources.list /etc/apt/sources.list.d/ubuntu.sources; do
        if [ -f "$source_file" ]; then
            sudo sed -E -i.bak \
                -e 's|https?://([a-z0-9.-]+\.)?archive\.ubuntu\.com/ubuntu|https://mirror.kakao.com/ubuntu|g' \
                -e 's|https?://security\.ubuntu\.com/ubuntu|https://mirror.kakao.com/ubuntu|g' \
                "$source_file"
        fi
    done

    sudo apt-get clean
    sudo timeout 60s apt-get -o Acquire::ForceIPv4=true \
        "${APT_TIMEOUT_OPTIONS[@]}" update >/dev/null 2>&1 &&
        sudo timeout 300s apt-get -o Acquire::ForceIPv4=true \
            "${APT_TIMEOUT_OPTIONS[@]}" install -y \
                docker.io docker-compose-v2 >/dev/null 2>&1
}

if ! command -v curl >/dev/null 2>&1 ||
    ! command -v jq >/dev/null 2>&1 ||
    ! command -v unzip >/dev/null 2>&1; then
    sudo timeout 180s apt-get "${APT_TIMEOUT_OPTIONS[@]}" update >/dev/null 2>&1 || true
    if ! sudo timeout 180s apt-get "${APT_TIMEOUT_OPTIONS[@]}" install -y \
        ca-certificates curl jq unzip >/dev/null 2>&1; then
        echo -e "${YELLOW}[경고] 공통 도구 설치가 실패하거나 180초를 넘겼습니다.${NC}"
    fi
fi

if docker_cli_ready; then
    echo -e "${GREEN}Docker와 Compose v2가 이미 설치되어 있어 패키지 설치를 건너뜁니다.${NC}"
    DOCKER_SUCCESS=true
    DOCKER_NOTE="기존 설치 재사용"
else
    if install_docker_from_official_repository && docker_cli_ready; then
        echo -e "${GREEN}Docker 공식 저장소 설치 완료${NC}"
        DOCKER_SUCCESS=true
        DOCKER_NOTE="공식 Docker 저장소 설치 완료"
    elif docker_cli_ready; then
        echo -e "${GREEN}공식 설치 결과 Docker와 Compose v2를 사용할 수 있습니다.${NC}"
        DOCKER_SUCCESS=true
        DOCKER_NOTE="공식 Docker 저장소 설치 완료"
    elif install_docker_from_ubuntu_repository && docker_cli_ready; then
        echo -e "${GREEN}Ubuntu docker.io와 Compose v2 설치 완료${NC}"
        DOCKER_SUCCESS=true
        DOCKER_NOTE="docker.io fallback 설치 완료"
    else
        echo -e "${RED}[오류] 공식 Docker와 docker.io 설치가 모두 실패했습니다.${NC}"
        DOCKER_NOTE="공식 Docker와 docker.io fallback 모두 실패"
    fi
fi

if [ "$DOCKER_SUCCESS" = true ]; then
    # daemon 시작도 무한히 기다리지 않는다. WSL에서는 service 명령이 대신 동작할 수 있다.
    if ! sudo timeout 60s systemctl enable --now docker >/dev/null 2>&1; then
        sudo timeout 60s service docker start >/dev/null 2>&1 || true
    fi
    sudo usermod -aG docker "$USER" 2>/dev/null || true
    record_step "1. Docker 설치" "SUCCESS" "$DOCKER_NOTE (그룹 추가됨)"
else
    record_step "1. Docker 설치" "FAILED" "$DOCKER_NOTE"
fi

echo ""

# ==============================================================================
# 2. AWS CLI 설치
# ==============================================================================
echo -e "${BOLD}${BLUE}=============================="
echo -e " 2. AWS CLI 설치"
echo -e "==============================${NC}"

AWS_SUCCESS=false
sudo apt-get install -y unzip curl >/dev/null 2>&1 || true

echo "AWS CLI 설치 파일 다운로드 중..."
if curl -fsSL "https://awscli.amazonaws.com/awscli-exe-linux-x86_64.zip" -o "awscliv2.zip"; then
    if unzip -oq awscliv2.zip; then
        if aws --version &>/dev/null; then
            echo "AWS CLI가 이미 설치되어 있습니다. --update로 업데이트를 진행합니다."
            if sudo ./aws/install --update >/dev/null 2>&1; then
                AWS_SUCCESS=true
                echo -e "${GREEN}AWS CLI 업데이트 완료${NC}"
            else
                echo -e "${YELLOW}[경고] AWS CLI 업데이트 실패, 기존 버전 유지${NC}"
                AWS_SUCCESS=true
            fi
        else
            if sudo ./aws/install >/dev/null 2>&1; then
                AWS_SUCCESS=true
                echo -e "${GREEN}AWS CLI 신규 설치 완료${NC}"
            else
                echo -e "${RED}[오류] AWS CLI 설치 스크립트 실행 실패${NC}"
            fi
        fi
        rm -rf awscliv2.zip aws/
    else
        echo -e "${RED}[오류] awscliv2.zip 압축 해제 실패${NC}"
        rm -f awscliv2.zip
    fi
else
    echo -e "${RED}[오류] AWS CLI 설치 파일 다운로드 실패${NC}"
fi

sync_environment_paths

if [ "$AWS_SUCCESS" = true ] || command -v aws &>/dev/null; then
    record_step "2. AWS CLI 설치" "SUCCESS" "설치 및 실행 확인됨"
else
    record_step "2. AWS CLI 설치" "FAILED" "설치 실패"
fi

echo ""

# ==============================================================================
# 3. Terraform 설치
# ==============================================================================
echo -e "${BOLD}${BLUE}=============================="
echo -e " 3. Terraform 설치"
echo -e "==============================${NC}"

TF_INSTALL_SUCCESS=false
sudo apt-get install -y gnupg software-properties-common >/dev/null 2>&1 || true

if curl -fsSL https://apt.releases.hashicorp.com/gpg 2>/dev/null | sudo gpg --dearmor --yes -o /usr/share/keyrings/hashicorp-archive-keyring.gpg 2>/dev/null; then
    echo "deb [signed-by=/usr/share/keyrings/hashicorp-archive-keyring.gpg] https://apt.releases.hashicorp.com $(lsb_release -cs) main" | \
      sudo tee /etc/apt/sources.list.d/hashicorp.list > /dev/null

    sudo apt-get update >/dev/null 2>&1 || true
    if sudo apt-get install -y terraform >/dev/null 2>&1; then
        echo -e "${GREEN}Terraform 설치 완료${NC}"
        TF_INSTALL_SUCCESS=true
    else
        echo -e "${RED}[오류] Terraform apt 패키지 설치 실패${NC}"
    fi
else
    echo -e "${RED}[오류] HashiCorp GPG 키 다운로드 실패${NC}"
fi

sync_environment_paths

if [ "$TF_INSTALL_SUCCESS" = true ] || command -v terraform &>/dev/null; then
    record_step "3. Terraform 설치" "SUCCESS" "설치 완료"
else
    record_step "3. Terraform 설치" "FAILED" "설치 실패"
fi

echo ""

# ==============================================================================
# 4. Terraform 프로바이더 캐시 설정
# ==============================================================================
echo -e "${BOLD}${BLUE}=============================="
echo -e " 4. Terraform 프로바이더 캐시 설정"
echo -e "==============================${NC}"

TF_CACHE_DIR="$HOME/.terraform.d/plugin-cache"
TF_RC_FILE="$HOME/.terraformrc"

if mkdir -p "$TF_CACHE_DIR"; then
    echo "캐시 디렉토리 생성/확인: $TF_CACHE_DIR"

    if grep -q "plugin_cache_dir" "$TF_RC_FILE" 2>/dev/null; then
        echo ".terraformrc에 이미 plugin_cache_dir 설정이 존재합니다."
    else
        cat >> "$TF_RC_FILE" <<EOF

plugin_cache_dir = "$TF_CACHE_DIR"
EOF
        echo ".terraformrc 설정 완료: $TF_RC_FILE"
    fi

    persist_path_entry "export TF_PLUGIN_CACHE_DIR=\"$TF_CACHE_DIR\"" "TF_PLUGIN_CACHE_DIR"
    export TF_PLUGIN_CACHE_DIR="$TF_CACHE_DIR"

    echo -e "${GREEN}Terraform 프로바이더 캐시 설정 완료${NC}"
    record_step "4. Terraform 캐시 설정" "SUCCESS" "$TF_CACHE_DIR"
else
    echo -e "${RED}[오류] 캐시 디렉터리 생성 실패${NC}"
    record_step "4. Terraform 캐시 설정" "FAILED" "디렉터리 생성 실패"
fi

echo ""

# ==============================================================================
# 5. Git 설치 및 실습 저장소 clone
# ==============================================================================
echo -e "${BOLD}${BLUE}=============================="
echo -e " 5. Git 설치 및 실습 저장소 clone"
echo -e "==============================${NC}"

REPO_URL="https://github.com/gasbugs/owasp-llm-lab-setup-guide.git"
REPO_DIR="$HOME/owasp-llm-lab-setup-guide"
GIT_SUCCESS=false

if ! command -v git &>/dev/null; then
    sudo apt-get install -y git >/dev/null 2>&1 || true
fi

if command -v git &>/dev/null; then
    if [ -d "$REPO_DIR" ]; then
        echo "저장소가 이미 존재합니다. git pull로 업데이트합니다."
        if git -C "$REPO_DIR" pull --ff-only; then
            echo -e "${GREEN}실습 저장소 업데이트 완료${NC}"
            GIT_SUCCESS=true
            record_step "5. Git 및 실습 저장소" "SUCCESS" "저장소 최신화 완료 (git pull)"
        else
            echo -e "${YELLOW}[경고] git pull 실패 (로컬 변경사항 확인 필요), 기존 저장소 유지${NC}"
            record_step "5. Git 및 실습 저장소" "WARNING" "저장소 존재 (pull 실패)"
        fi
    else
        if git clone "$REPO_URL" "$REPO_DIR"; then
            echo -e "${GREEN}실습 저장소 clone 완료: $REPO_DIR${NC}"
            GIT_SUCCESS=true
            record_step "5. Git 및 실습 저장소" "SUCCESS" "신규 clone 완료"
        else
            echo -e "${RED}[오류] 실습 저장소 clone 실패${NC}"
            record_step "5. Git 및 실습 저장소" "FAILED" "clone 실패"
        fi
    fi
else
    echo -e "${RED}[오류] Git 패키지 설치 실패${NC}"
    record_step "5. Git 및 실습 저장소" "FAILED" "git 미설치"
fi

echo ""

# ==============================================================================
# 6. Node.js / npm 설치 및 환경변수(PATH) 자동 보정
# ==============================================================================
echo -e "${BOLD}${BLUE}=============================="
echo -e " 6. Node.js / npm 설치 및 환경 설정"
echo -e "==============================${NC}"

NODE_SETUP_SUCCESS=false

# NodeSource 저장소 설정 및 설치
if curl -fsSL https://deb.nodesource.com/setup_22.x 2>/dev/null | sudo -E bash - >/dev/null 2>&1; then
    if sudo apt-get install -y nodejs; then
        NODE_SETUP_SUCCESS=true
    fi
fi

# 만약 NodeSource 실패 시 일반 apt 패키지로 fallback 시도
if ! command -v node &>/dev/null; then
    echo -e "${YELLOW}NodeSource 설치 실패로 기본 저장소에서 nodejs/npm 설치를 시도합니다.${NC}"
    sudo apt-get update >/dev/null 2>&1 || true
    sudo apt-get install -y nodejs npm >/dev/null 2>&1 || true
fi

# npm 별도 설치 필요 여부 점검 (일부 배포판 대응)
if command -v node &>/dev/null && ! command -v npm &>/dev/null; then
    echo "npm 패키지 별도 설치 진행 중..."
    sudo apt-get install -y npm >/dev/null 2>&1 || true
fi

# ------------------------------------------------------------------------------
# npm 환경 변수 및 글로벌 패키지 디렉토리 자동 보정 (권한 에러 방지 및 PATH 등록)
# ------------------------------------------------------------------------------
NPM_GLOBAL_DIR="$HOME/.npm-global"
mkdir -p "$NPM_GLOBAL_DIR/bin" "$NPM_GLOBAL_DIR/lib" 2>/dev/null || true

if command -v npm &>/dev/null; then
    npm config set prefix "$NPM_GLOBAL_DIR" 2>/dev/null || true
    echo "npm 전역 prefix 설정: $NPM_GLOBAL_DIR"
fi

# 현재 셸 및 설정 파일에 npm 글로벌 bin PATH 등록
export PATH="$NPM_GLOBAL_DIR/bin:$PATH"
persist_path_entry "export PATH=\"\$HOME/.npm-global/bin:\$PATH\"" ".npm-global/bin"

sync_environment_paths

if command -v node &>/dev/null && command -v npm &>/dev/null; then
    echo -e "${GREEN}Node.js & npm 설치 및 환경변수 등록 완료${NC}"
    record_step "6. Node.js / npm" "SUCCESS" "$(node -v) / npm $(npm -v)"
elif command -v node &>/dev/null; then
    echo -e "${YELLOW}[경고] Node.js는 설치되었으나 npm을 찾을 수 없습니다.${NC}"
    record_step "6. Node.js / npm" "WARNING" "Node.js만 설치됨 (npm 누락)"
else
    echo -e "${RED}[오류] Node.js / npm 설치 실패${NC}"
    record_step "6. Node.js / npm" "FAILED" "설치 실패"
fi

echo ""

# ==============================================================================
# 7. Antigravity CLI (agy) 설치 및 PATH/환경변수 자동 보정
# ==============================================================================
echo -e "${BOLD}${BLUE}=============================="
echo -e " 7. Antigravity CLI (agy) 설치 및 PATH 보정"
echo -e "==============================${NC}"

# 1) 필수 기본 패키지 점검
sudo apt-get install -y curl ca-certificates git >/dev/null 2>&1 || true

# 2) Antigravity CLI 공식 설치 스크립트 실행
echo "Antigravity CLI 다운로드 및 설치 진행 중..."
if curl -fsSL https://antigravity.google/cli/install.sh 2>/dev/null | bash; then
    echo "공식 설치 스크립트 실행 완료"
else
    echo -e "${YELLOW}[경고] 공식 설치 스크립트 실행 중 경고 또는 에러가 반환되었습니다. 로컬 바이너리 및 PATH를 점검합니다.${NC}"
fi

# ------------------------------------------------------------------------------
# agy PATH 자동 감지 및 보정 핵심 로직
# ------------------------------------------------------------------------------
# 1. candidate 경로 수색 및 PATH 추가
AGY_CANDIDATES=(
    "$HOME/.local/bin"
    "$HOME/.antigravity/bin"
    "$HOME/.gemini/antigravity-cli/bin"
    "/usr/local/bin"
    "/usr/bin"
)

for c_path in "${AGY_CANDIDATES[@]}"; do
    if [ -d "$c_path" ]; then
        if [[ ":$PATH:" != *":$c_path:"* ]]; then
            export PATH="$c_path:$PATH"
        fi
    fi
done

# 2. 영구 설정 파일(.bashrc, .profile)에 PATH 등록 (중복 방지)
persist_path_entry "export PATH=\"\$HOME/.local/bin:\$HOME/.antigravity/bin:\$PATH\"" ".local/bin"

# 3. 만약 command -v agy가 안 잡히면 홈 디렉터리 내 바이너리 탐색 및 복구
if ! command -v agy &>/dev/null; then
    echo "agy 바이너리 자동 탐색 중..."
    FOUND_AGY=$(find "$HOME/.local/bin" "$HOME/.antigravity" "$HOME/.gemini" "$HOME" -maxdepth 4 -type f -name "agy" -perm /111 2>/dev/null | head -n 1)
    if [ -n "$FOUND_AGY" ]; then
        FOUND_DIR=$(dirname "$FOUND_AGY")
        export PATH="$FOUND_DIR:$PATH"
        mkdir -p "$HOME/.local/bin"
        ln -sf "$FOUND_AGY" "$HOME/.local/bin/agy" 2>/dev/null || true
        echo -e "${GREEN}agy 바이너리 발견 및 링크 완료: $FOUND_AGY -> $HOME/.local/bin/agy${NC}"
    fi
fi

sync_environment_paths

if command -v agy &>/dev/null; then
    AGY_VER=$(agy --version 2>/dev/null || echo "버전 확인 가능")
    echo -e "${GREEN}Antigravity CLI (agy) 설정 완료 (경로: $(which agy))${NC}"
    record_step "7. Antigravity CLI" "SUCCESS" "$AGY_VER"
else
    echo -e "${RED}[오류] agy 명령어를 찾을 수 없습니다. 설치 로그를 확인해주세요.${NC}"
    record_step "7. Antigravity CLI" "FAILED" "바이너리 탐색 실패"
fi

echo ""

# ==============================================================================
# 최종 요약 및 버전/상태 통계 리포트 출력
# ==============================================================================
echo -e "${BOLD}${CYAN}==============================================================================${NC}"
echo -e "${BOLD}${CYAN}                         설치 단계별 실행 결과 요약                           ${NC}"
echo -e "${BOLD}${CYAN}==============================================================================${NC}"
printf "  %-32s | %-12s | %-26s\n" "단계(Step)" "상태(Status)" "비고(Note)"
echo "------------------------------------------------------------------------------"

TOTAL_STEPS=${#STEP_NAMES[@]}
SUCCESS_COUNT=0
WARN_COUNT=0
FAIL_COUNT=0

for i in "${!STEP_NAMES[@]}"; do
    NAME="${STEP_NAMES[$i]}"
    STATUS="${STEP_STATUSES[$i]}"
    NOTE="${STEP_NOTES[$i]}"

    case "$STATUS" in
        "SUCCESS")
            STATUS_FMT="${GREEN}[ 성공 ]${NC}"
            ((SUCCESS_COUNT++))
            ;;
        "WARNING")
            STATUS_FMT="${YELLOW}[ 경고 ]${NC}"
            ((WARN_COUNT++))
            ;;
        "FAILED")
            STATUS_FMT="${RED}[ 실패 ]${NC}"
            ((FAIL_COUNT++))
            ;;
        *)
            STATUS_FMT="[ $STATUS ]"
            ;;
    esac

    printf "  %-30s | %b | %s\n" "$NAME" "$STATUS_FMT" "$NOTE"
done

echo "------------------------------------------------------------------------------"
echo -e "총 ${BOLD}$TOTAL_STEPS${NC}개 단계 중: ${GREEN}성공 $SUCCESS_COUNT${NC}, ${YELLOW}경고 $WARN_COUNT${NC}, ${RED}실패 $FAIL_COUNT${NC}"
echo ""

echo -e "${BOLD}${CYAN}==============================================================================${NC}"
echo -e "${BOLD}${CYAN}                         설치 도구 버전 최종 확인                             ${NC}"
echo -e "${BOLD}${CYAN}==============================================================================${NC}"

check_tool_detail() {
    local name="$1"
    local bin_name="$2"
    local ver_cmd="$3"

    local bin_path
    bin_path=$(command -v "$bin_name" 2>/dev/null || echo "")

    if [ -n "$bin_path" ]; then
        local ver_str
        ver_str=$(eval "$ver_cmd" 2>/dev/null | head -n 1)
        if [ -n "$ver_str" ]; then
            printf "  %-18s : ${GREEN}%-24s${NC} (%s)\n" "$name" "$ver_str" "$bin_path"
        else
            printf "  %-18s : ${YELLOW}%-24s${NC} (%s)\n" "$name" "[버전 출력 없음]" "$bin_path"
        fi
    else
        printf "  %-18s : ${RED}%-24s${NC} (%s)\n" "$name" "[미설치 또는 PATH 누락]" "경로 없음"
    fi
}

check_tool_detail "Docker"          "docker"    "sudo docker version --format '{{.Server.Version}}' 2>/dev/null || docker --version 2>/dev/null"
check_tool_detail "AWS CLI"         "aws"       "aws --version"
check_tool_detail "Terraform"       "terraform" "terraform -version | head -n 1"
check_tool_detail "Git"             "git"       "git --version"
check_tool_detail "Node.js"         "node"      "node -v"
check_tool_detail "npm"             "npm"       "npm -v"
check_tool_detail "agy CLI"         "agy"       "agy --version"

echo ""
echo -e "${BOLD}${CYAN}==============================================================================${NC}"
echo -e "${BOLD}${CYAN}                         주요 환경 설정 정보                                  ${NC}"
echo -e "${BOLD}${CYAN}==============================================================================${NC}"
echo -e "  [Terraform 캐시]    : ${TF_CACHE_DIR:-$HOME/.terraform.d/plugin-cache}"
echo -e "  [Terraform RC]      : ${TF_RC_FILE:-$HOME/.terraformrc}"
echo -e "  [실습 저장소 경로]  : ${REPO_DIR:-$HOME/owasp-llm-lab-setup-guide}"
echo -e "  [npm 글로벌 경로]   : ${NPM_GLOBAL_DIR:-$HOME/.npm-global/bin}"
echo -e "  [현재 PATH]         : $PATH"
echo ""

if [ "$FAIL_COUNT" -gt 0 ]; then
    echo -e "${YELLOW}※ 일부 단계에서 실패가 발생했습니다. 위 요약 테이블과 메시지를 확인해 주세요.${NC}"
else
    echo -e "${GREEN}※ 모든 구성 요소가 성공적으로 설치 및 설정되었습니다!${NC}"
fi

echo -e "※ 환경변수 즉시 반영: ${BOLD}source ~/.bashrc${NC} 또는 ${BOLD}source ~/.profile${NC}"
echo -e "※ agy CLI 인증:       ${BOLD}agy${NC} (최초 실행 시 Google 계정 로그인)"
echo -e "${BOLD}${CYAN}==============================================================================${NC}"

# Docker 그룹 권한은 현재 셸에는 바로 반영되지 않는다.
# 설치가 모두 끝난 뒤 사용자를 Docker 그룹에 다시 등록하고 새 로그인 셸을 연다.
sudo usermod -aG docker "$USER" && su - "$USER"
