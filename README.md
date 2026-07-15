# AWS 보안 설정 자동 조치 파이프라인

> 클라우드 보안 설정 결함(Misconfiguration)을 **탐지 → 자동 조치 → 조치
> 매뉴얼화**까지 하나의 파이프라인으로 관통하는 클라우드 보안 자동화 프로젝트.
> 상용 클라우드 보안 도구의 핵심 흐름을 AWS 네이티브 서비스로 구현한다.

## 이 프로젝트는

상용 클라우드 보안 도구(AWS Security Hub, Wiz 등)가 수행하는 **탐지 → 조치 → 운영** 흐름을
AWS 네이티브 서비스(Config·EventBridge·Lambda)로 구현한다.

- **이벤트 기반 상시 대응**: 주기적으로 계정을 스캔하는 배치 방식이 아니라,
  설정이 바뀌는 "순간"을 이벤트로 잡아 조치한다.
- **단순 탐지가 아니라 자동 조치**: 결함을 찾는 데 그치지 않고, 조치 Lambda가
  리소스를 안전한 상태로 되돌린다(멱등·비파괴).
- **조치를 매뉴얼로 운영**: 모든 자동 조치는 대응 런북(`docs/runbooks/`)과
  1:1로 짝을 이루고, 자동 조치가 위험하거나 불가능한 경우(IAM·RDS)는 승인
  기반 또는 수동 런북으로 다룬다.

## 아키텍처

세 계층으로 구성된다: **탐지(Detect)** → **조치(Remediate)** → **운영(Operate)**.

![AWS 보안 설정 자동 조치 파이프라인 아키텍처](docs/images/architecture.svg)

자세한 구성요소 역할·데이터 흐름은 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)
참고.

## 구현 시나리오

각 시나리오는 "취약 리소스 + Config 규칙 + 조치 + 런북"을 한 세트로 관통한다.

| 시나리오 | Config 규칙 | 조치 방식 | 런북 |
|----------|-------------|-----------|------|
| S3 퍼블릭 노출 | `S3_BUCKET_PUBLIC_READ_PROHIBITED` | 자동 (Block Public Access 복구) | [s3-public-access](docs/runbooks/s3-public-access.md) |
| IAM 과도 권한 (CIEM) | `IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS` | 탐지·알림(SNS) + **승인 기반 조치** (자동 차단 안 함) | [iam-excessive-privilege](docs/runbooks/iam-excessive-privilege.md) |
| S3 미암호화 (KMS) | `S3_DEFAULT_ENCRYPTION_KMS` | 자동 (SSE-KMS 제자리 적용) | [s3-kms-encryption](docs/runbooks/s3-kms-encryption.md) |
| EBS 기본 암호화 | `EC2_EBS_ENCRYPTION_BY_DEFAULT` | 자동 (계정 기본 암호화 ON, 예방형) | [ebs-encryption-default](docs/runbooks/ebs-encryption-default.md) |
| RDS 저장 암호화 | (탐지 선택) | **수동** (제자리 조치 불가) | [rds-storage-encryption](docs/runbooks/rds-storage-encryption.md) |

설계 포인트: **암호화 조치는 하나가 아니다.** 리소스별 제자리 암호화 가능성에
따라 조치 스펙트럼이 갈린다 (S3 = 완전 자동 → EBS = 예방만 자동 → RDS = 수동).
IAM은 자동 차단이 서비스 중단을 부를 수 있어 "탐지·알림 우선, 조치는 승인 기반"을
기본으로 둔다.

## 공통 인프라 (로깅·가시화)

여러 시나리오를 가로질러 로그와 현황을 함께 다루는 계층이다.

- **로그 통합** (`terraform/modules/log-lake/`): CloudTrail·VPC Flow Logs·조치
  로그를 하나의 S3 로그 레이크에 모아 Athena/Glue로 조회한다. 조치 이력과 실제
  API 호출(CloudTrail)을 한 곳에서 교차 검증한다.
  검증 절차: [로그 레이크 배포·검증](docs/guide/log-lake-deploy-verify.md).
- **가시화** (`terraform/modules/dashboard/`): 조치 로그(metric filter →
  `AutoFix/Remediation`)와 Config 준수율(`AutoFix/Compliance`)을 하나의 CloudWatch
  대시보드로 모아 "언제 무엇이 탐지·조치됐는지"를 한눈에 보여준다.
  검증 절차: [대시보드 배포·검증](docs/guide/dashboard-deploy-verify.md).
- **웹 대시보드** (`dashboard/`): 위 CloudWatch 대시보드와 **병행 운영**하는 로컬 실행
  대시보드. 커스텀 메트릭을 우회하고 AWS Config·CloudWatch Logs를 직접 읽어,
  메트릭 차원으로는 담을 수 없는 정보(지금 위반 중인 리소스 ID, 적용된 KMS 키,
  변경된 정책 버전)까지 시나리오별로 보여준다. AWS 리소스를 새로 만들지 않는다
  (읽기 전용 조회, 비용 0원). 실행법: [dashboard/README.md](dashboard/README.md).

## 기술 스택

| 영역 | 사용 기술 |
|------|-----------|
| IaC | Terraform (>= 1.5), AWS Provider ~> 6.0 |
| 자동화 스크립트 | Python 3.12 + boto3 |
| 탐지 | AWS Config (관리형 규칙) |
| 이벤트 연결 | Amazon EventBridge |
| 자동 조치 | AWS Lambda |
| 로깅/분석 | CloudWatch Logs → S3 로그 레이크 (Athena/Glue) |
| 가시화 | CloudWatch 대시보드 + 로컬 웹 대시보드 (Python 표준 라이브러리 + boto3, 의존성 없는 바닐라 JS) |
| 리전 | ap-northeast-2 (서울) 기본 |

## 리포 구조

```
aws-sec-autofix/
├── terraform/
│   ├── main.tf / variables.tf / outputs.tf   # 모듈 오케스트레이션
│   └── modules/
│       ├── config-baseline/                  # 계정 Config Recorder(싱글턴)
│       ├── s3-public-access/                  # 시나리오 1
│       ├── iam-excessive-privilege/          # 시나리오 2
│       ├── s3-kms-encryption/                # 시나리오 3a
│       ├── ebs-encryption-default/           # 시나리오 3b
│       ├── log-lake/                         # 로그 통합
│       └── dashboard/                        # 가시화 (CloudWatch)
├── lambda/                                    # 조치·처리 함수(항목별 handler.py)
├── dashboard/                                 # 가시화 (로컬 웹 대시보드)
│   ├── serve.py                              # 로컬 서버 + Config·Logs 읽기 전용 조회
│   └── static/                               # 의존성 없는 HTML/CSS/JS
└── docs/
    ├── ARCHITECTURE.md                        # 아키텍처·데이터 흐름
    ├── deploy-iam-policy.json                 # 배포 주체용 IAM 정책
    ├── runbooks/                              # 조치 매뉴얼(항목별)
    └── guide/                                 # 배포·검증 가이드(시나리오별)
```

## 배포 & 검증

> ⚠️ 실제 배포는 AWS 요금과 의도적 취약 리소스 생성을 수반한다. 격리된 전용
> 계정에서만 진행하고, 검증이 끝나면 반드시 `terraform destroy` 한다.

1. **전제**: Terraform 배포 주체에 `docs/deploy-iam-policy.json` 권한을 부여한다
   (격리 계정이면 `AdministratorAccess`로 대체 가능). `terraform/terraform.tfvars`에
   프로필·리전·알림 이메일 등을 지정한다.
2. **배포**:
   ```bash
   cd terraform
   terraform init
   terraform plan     # 생성될 리소스 검토
   terraform apply    # yes 입력
   ```
3. **시나리오별 검증** (각 가이드가 취약 리소스 유발 → 자동 조치 → `COMPLIANT`
   전환까지 한 사이클을 안내):
   - [S3 퍼블릭 노출](docs/guide/s3-public-access-deploy-verify.md)
   - [IAM 과도 권한](docs/guide/iam-excessive-privilege-deploy-verify.md)
   - [저장 데이터 암호화 (S3-KMS · EBS)](docs/guide/encryption-at-rest-deploy-verify.md)
   - [로그 통합 (로그 레이크)](docs/guide/log-lake-deploy-verify.md)
   - [가시화 (대시보드)](docs/guide/dashboard-deploy-verify.md)
4. **정리**:
   ```bash
   terraform destroy
   ```

## 안전·비용 원칙

- **최소 권한**: 모든 IAM 역할/정책은 해당 작업에 꼭 필요한 액션만 부여한다
  (와일드카드 남용 금지).
- **비파괴 조치**: 자동 조치는 "노출 차단·안전화"만 수행하고 리소스 삭제 등
  파괴적 동작은 하지 않는다(예외는 사람이 승인).
- **멱등성**: 조치 함수는 여러 번 실행돼도 안전하다.
- **의도적 취약 리소스 표시**: 의도적으로 만든 취약 리소스에는 `Purpose =
  intentionally-vulnerable` 태그를 붙여 실제 리소스와 구분한다.
- **destroy 전제**: 배포한 모든 리소스는 작업 종료 시 `terraform destroy`로 정리한다.

## 향후 확장

- **Bedrock / 컨테이너 보안 정책 테스트**: 생성형 AI(Bedrock)·컨테이너 워크로드의
  보안 정책 위반을 같은 3계층 구조(탐지·조치·운영)로 확장하는 것을 후보로 둔다.
  구현 시 런북·배포 검증 가이드를 함께 추가한다.

## 문서

- [ARCHITECTURE.md](docs/ARCHITECTURE.md): 전체 구조·데이터 흐름·확장 원칙
- [docs/runbooks/](docs/runbooks/): 항목별 조치 매뉴얼
- [docs/guide/](docs/guide/): 시나리오별 배포·검증 가이드
