# LDL 전용 EC2

이 모듈은 LDL용 Ubuntu EC2 한 대를 준비한다. EC2의 IAM 역할·프로파일·보안 그룹은 수업용과 별개다. 인스턴스는 `m6a.large`이고, 루트 볼륨은 암호화한 gp3 100 GiB다. 기본 VPC와 기본 서브넷이 있는 `us-east-1` 계정에서 실행한다.

## 운영자 배포

AWS CLI와 Terraform이 이미 설치된 Bash 터미널을 사용한다. AWS 콘솔 로그인 창에서 배포할 수강생 계정의 권한을 선택한다. 브라우저를 같은 환경에서 열 수 없으면 첫 명령에 `--remote`를 붙이고 브라우저에 표시된 인증 코드를 터미널에 입력한다.

```bash
aws login --profile ldl-login --region us-east-1
aws configure set credential_process \
  'aws configure export-credentials --profile ldl-login --format process' --profile ldl-terraform
export AWS_PROFILE=ldl-terraform
aws sts get-caller-identity --region us-east-1
```

`Account`가 배포할 계정인지 확인한다. `ldl-terraform` 프로필은 Terraform AWS 공급자에 로그인 세션의 임시 자격 증명을 전달한다. `learner_ipv4_cidr`에는 수강생의 PC에서 확인한 공인 IPv4 한 개를 `/32`로 입력한다.

```bash
cd infrastructure/terraform-ldl
terraform init
read -r -p '수강생 PC 공인 IPv4 (/32 포함): ' LEARNER_CIDR
terraform plan -var="learner_ipv4_cidr=$LEARNER_CIDR" -out=ldl.plan
terraform apply ldl.plan
```

EC2 상태가 실행 중이 된 뒤에도 첫 부팅에서 Docker·AWS CLI 설치와 LDL 이미지 빌드가 진행된다. EC2 콘솔의 시스템 로그에서 `LDL_BOOTSTRAP_READY`를 확인한 다음 `terraform output -raw ldl_url`로 나온 주소를 수강생에게 전달한다. 수강생은 브라우저에서 접속한다. 이 모듈의 보안 그룹은 수강생 PC의 `9010–9015/tcp`만 허용한다.

LDL 홈과 P00은 바로 열 수 있다. 보조 Grafana 화면을 사용할 때는 운영자가 AWS Secrets Manager에서 이 LDL 인스턴스의 두 로그인 정보를 확인해 해당 수강생에게 전달한다. 첫 부팅에서 생성한 비밀번호는 Terraform 입력과 부팅 로그에 들어가지 않는다. 이 모듈은 로그인 정보 보관용 Secrets Manager 시크릿 한 개도 생성한다.

```bash
aws secretsmanager get-secret-value --region us-east-1 \
  --secret-id "$(terraform output -raw grafana_secret_arn)" \
  --query SecretString --output text
```

첫 부팅은 암호화한 루트 볼륨에 4 GiB 스왑을 설정하고, 이미지 빌드 동시성을 1로 제한한다. 설치가 끝나면 LDL 사용자 서비스가 이후 EC2 시작 시 기존 데이터와 함께 컨테이너를 시작하고 새 공인 IPv4를 반영한다. EC2를 중지한 뒤 다시 시작한 경우 현재 공인 IPv4를 EC2 콘솔에서 확인해 접속 주소에 사용한다.

부팅에 실패하면 시스템 로그에서 `LDL_BOOTSTRAP_FAILED` 앞의 오류를 확인한다. Terraform 상태 파일로 해당 AWS 계정의 자원을 관리한다. 최초 설치 코드는 지정한 Git 커밋을 사용한다.

역할에는 P01-01의 Nova Lite 호출 권한을 넣는다. 후속 미션의 S3·Knowledge Base 자원과 임시 인증은 미션 실행 범위다. 현재 P01-02·03 Gateway에는 EC2 역할로 사용할 수 없는 `GetFederationToken` 호출이 남아 있어 별도 수정과 검증이 필요하다.

## 수업용 EC2

CloudShell에서 수업용 EC2만 별도로 만든다. 수강생은 SSH로 접속해 강의의 Docker·AWS CLI 설치 명령과 이후 실습 명령을 실행한다.

```bash
read -r -p '수강생 PC 공인 IPv4 (/32 포함): ' LEARNER_CIDR
bash infrastructure/scripts/create-class-ec2.sh "$LEARNER_CIDR"
```

스크립트는 수업용 EC2에 `m6a.large`, 전용 보안 그룹 및 `owasp-llm-bedrock-ec2` 역할을 사용한다. 해당 역할은 처음 만들 때 권한을 붙이지 않으며 각 실습에서 필요한 권한을 부여한다.
