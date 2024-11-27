# Breach-LOL
# Terraform AWS VPC 인프라 구축

이 프로젝트는 Terraform을 이용해 AWS에서 세 개의 서로 다른 VPC(Virtual Private Cloud)를 구성하는 코드입니다. 이 인프라는 서비스의 분리와 보안을 보장하기 위해 설계되었습니다:

- **내부망 VPC**: 기업 내부 시스템 및 데이터베이스가 위치한 영역.
- **웹 VPC**: 퍼블릭 웹 서비스가 운영되는 영역으로, 외부 접속이 허용되는 구역.
- **모빌리티 플랫폼 VPC**: 모바일 기기를 통해 모빌리티 시스템을 제어하고 사용자 서비스를 제공하는 영역.

---

## 주요 기능

### 1. 내부망 VPC
- 기업 내부 전용 시스템을 위한 설계.
- 데이터베이스와 민감한 시스템을 호스팅.
- 외부 인터넷 접근 불가.

### 2. 웹 VPC
- 인터넷에서 접근 가능한 퍼블릭 서비스 운영.
- 웹 트래픽을 처리하며 보안 설정 강화.

### 3. 모빌리티 플랫폼 VPC
- 모빌리티 시스템을 제어하기 위한 모바일 기기 지원.
- 사용자 서비스와 외부 API 상호작용을 안전하게 처리.

---

## 사전 준비

### 1. Terraform 설치
Terraform은 [Terraform 공식 웹사이트](https://www.terraform.io/downloads.html)에서 설치할 수 있습니다.

### 2. AWS CLI 설치 및 구성
AWS CLI를 설치하고, 아래 명령어로 특정 계정을 설정합니다:

```bash
aws configure --profile <profile_name>
```
- <profile_name>: 사용할 AWS 계정 이름을 입력합니다.
- 입력해야 할 항목
-- AWS Access Key ID
-- AWS Secret Access Key
-- 기본 리전(e.g., ap-northeast-2)
-- 출력 형식(json 권장)
###  3. Terraform에서 프로파일 지정
- AWS CLI에서 설정한 프로파일 이름을 Terraform provider 블록에서 참조해야 합니다.

```hcl
provider "aws" {
  profile = "your-profile-name"  # AWS CLI에서 설정한 프로파일 이름
  region  = "ap-northeast-2"
}
```
###  4. AWS 권한 확인
VPC, 서브넷, 보안 그룹 등 AWS 리소스를 생성할 수 있는 권한이 필요합니다.

---
## 실행 방법
Terraform을 이용해 인프라를 구축하려면 아래 단계를 따르세요
1. Terraform 초기화
작업 디렉토리를 초기화하고 필요한 Terraform 제공자와 모듈을 다운로드합니다.
```bash
terraform init
```
2. 계획 확인
Terraform이 생성, 업데이트 또는 삭제할 리소스에 대한 실행 계획을 생성하고 검토합니다.
```bash
terraform plan
```
3. 인프라 배포
실행 계획을 실행해 AWS에 인프라를 배포합니다.
```bash
terraform apply
```
4. 인프라 삭제
생성한 모든 리소스를 삭제하고 정리하려면 아래 명령어를 사용합니다.
```bash
terraform destroy
```
---
## 주의사항
- AWS CLI 설정: Terraform이 AWS에 접근하려면 aws configure --profile <profile_name> 명령어로 계정을 설정하고, Terraform의 provider 블록에서 해당 프로파일 이름을 참조해야 합니다.
- 비용 발생: Terraform 실행 시 AWS 리소스 생성에 따른 비용이 발생할 수 있습니다.
- 적용 전 확인: 설정 파일 변경 후 항상 terraform plan으로 계획을 확인한 뒤 적용하세요.
- 리소스 정리: 필요하지 않은 리소스를 삭제하지 않으면 불필요한 비용이 발생할 수 있습니다. 사용 후 반드시 terraform destroy를 실행하세요.
