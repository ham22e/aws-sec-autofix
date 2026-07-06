# 배포 & 콘솔 검증 가이드 — S3 퍼블릭 노출

`terraform apply` 로 배포한 뒤, **AWS 콘솔**에서 탐지 → 자동 조치 → `COMPLIANT`
전환까지 한 사이클을 눈으로 확인하는 절차다.
(CLI 중심 검증·조치 절차는 `docs/runbooks/s3-public-access.md` 참고.)

> 리전: **ap-northeast-2 (서울)**. 콘솔 우상단 리전이 서울인지 먼저 확인한다.
> 다른 리전을 보고 있으면 리소스가 안 보인다.

리소스 이름은 `project_name`(기본 `autofix`) 접두사를 쓴다.

| 리소스 | 이름(기본값) |
|--------|--------------|
| 취약 S3 버킷 | `autofix-public-<임의suffix>` |
| Config 규칙 | `autofix-s3-bucket-public-read-prohibited` |
| EventBridge 규칙 | `autofix-s3-public-read-noncompliant` |
| 조치 Lambda | `autofix-s3-remediation` |
| Lambda 로그 그룹 | `/aws/lambda/autofix-s3-remediation` |
| Config Recorder | `autofix-recorder` |

---

## 0. 사전 준비

1. `terraform/terraform.tfvars` 에 배포 프로필 지정(예: `aws_profile = "내프로필"`).
2. 그 프로필/자격증명에 배포 권한 부여 — `docs/deploy-iam-policy.json` 또는
   (격리 계정이면) `AdministratorAccess`.
3. 자격증명 확인:
   ```bash
   AWS_PROFILE=<프로필> aws sts get-caller-identity
   ```

---

## 1. 배포 (terraform apply)

```bash
cd terraform
terraform plan      # 생성될 리소스 검토
terraform apply     # yes 입력
```

`apply` 완료 후 출력(outputs)에서 실제 이름을 확인한다:
```bash
terraform output
# vulnerable_bucket   = "autofix-public-xxxxxxxx"
# config_rule_name    = "autofix-s3-bucket-public-read-prohibited"
# lambda_function_name= "autofix-s3-remediation"
```

> ⚠️ `apply` 직후 취약 버킷은 **실제로 퍼블릭 read 가 열린 상태**다. 격리 테스트
> 계정에서만 진행하고, 검증이 끝나면 반드시 `terraform destroy` 한다.

---

## 2. 배포 리소스 확인 (콘솔)

### 2-1. 취약 S3 버킷
- **S3** → 버킷 목록에서 `autofix-public-...` 클릭.
- **속성(Properties)** → 태그에 `Purpose = intentionally-vulnerable` 확인.
- **권한(Permissions)** 탭:
  - **퍼블릭 액세스 차단(Block public access)** = **4종 모두 꺼짐(Off)** — 취약 상태.
  - 목록 상단 배지에 **"퍼블릭(Public)"** 표시가 뜬다.
  - **버킷 정책(Bucket policy)** 에 `Principal: *`, `s3:GetObject` 문 존재.

### 2-2. AWS Config
- **AWS Config** → **설정(Settings)** 에서 Recorder 가 **켜짐(Recording is on)** 인지 확인.
- **규칙(Rules)** → `autofix-s3-bucket-public-read-prohibited` 존재 확인.

### 2-3. EventBridge / Lambda (연결 확인)
- **Amazon EventBridge** → **규칙(Rules)** → 이벤트 버스 `default` → `autofix-s3-public-read-noncompliant`
  → **대상(Target)** 이 조치 Lambda 인지 확인.
- **Lambda** → 함수 `autofix-s3-remediation` → **구성(Configuration) → 트리거(Triggers)**
  에 EventBridge 가 연결돼 있는지 확인.

---

## 3. 탐지 확인 — NON_COMPLIANT (Config 콘솔)

Config 최초 평가는 **수 분** 걸릴 수 있다. 즉시 보고 싶으면 강제 재평가한다.

- **AWS Config → 규칙 →** 해당 규칙 클릭.
- 바로 뜨지 않으면 우상단 **작업(Actions) → 재평가(Re-evaluate)** 클릭 후 새로고침.
- 규칙 상태가 **`NON_COMPLIANT`**, 범위 내 리소스에 취약 버킷이 뜨면 탐지 성공.

> 자동 조치가 매우 빠르면, 이 화면을 볼 때 이미 `COMPLIANT` 로 바뀌어 있을 수 있다.
> 그럴 땐 아래 **4. 조치 로그**와 **규칙의 컴플라이언스 타임라인/이력**으로
> "NON_COMPLIANT → 조치 → COMPLIANT" 흐름을 확인한다.

---

## 4. 자동 조치 확인 — Lambda 로그 & BPA 변경

### 4-1. 조치 로그 (CloudWatch Logs)
- **CloudWatch → 로그 그룹(Log groups) →** `/aws/lambda/autofix-s3-remediation`.
- 최신 로그 스트림에서 **JSON 한 줄** 조치 로그 확인:
  ```json
  {"applied":{"BlockPublicAcls":true,"BlockPublicPolicy":true,"IgnorePublicAcls":true,"RestrictPublicBuckets":true},"bucket":"autofix-public-xxxx","compliance_before":"NON_COMPLIANT","control":"s3-public-access","event_type":"remediation","status":"applied","timestamp":"..."}
  ```
  - `status=applied` = 조치 수행됨. `already_compliant` = 이미 안전(멱등).
- (대안) **Lambda → 함수 → 모니터링(Monitor) → CloudWatch 로그 보기** 로도 이동 가능.

### 4-2. 버킷이 안전해졌는지 (S3 콘솔)
- **S3 →** 취약 버킷 → **권한** 탭 → **퍼블릭 액세스 차단이 4종 모두 켜짐(On)** 으로
  바뀌었는지 확인. 목록의 "퍼블릭" 배지도 사라진다.
- 버킷 정책은 **그대로 남아 있다** — 조치는 노출만 차단하는 **비파괴** 방식이기 때문.

---

## 5. COMPLIANT 전환 확인 (Config 콘솔)

- BPA 가 켜지면 그 구성 변경으로 Config 가 **자동 재평가**한다(변경 트리거 규칙).
- **AWS Config → 규칙 →** 해당 규칙이 **`COMPLIANT`** 로 바뀌면 한 사이클 완료.
- 필요하면 **작업 → 재평가**로 즉시 갱신.

여기까지 오면 **탐지(NON_COMPLIANT) → 자동 조치(로그+BPA on) → COMPLIANT** 한 사이클이
재현된 것이다 (DoD 충족).

---

## 6. 재검증 & 정리

- **다시 취약 상태로 리셋**(재검증): Lambda 가 켠 BPA 때문에 Terraform 상태와 실제가
  어긋난다. 아래로 다시 취약 상태로 되돌릴 수 있다.
  ```bash
  terraform apply   # BPA 를 다시 4종 off 로 되돌림 → NON_COMPLIANT 재현
  ```
  (조치 후 `terraform plan` 에 BPA 드리프트가 뜨는 것은 정상이다.)

  > ⚠️ **재검증 시 EventBridge 규칙은 반드시 켜둔 채로** 취약화(BPA off)해야 한다.
  > 자동 조치는 컴플라이언스가 **바뀌는 순간**(`COMPLIANT → NON_COMPLIANT` 전환)에만
  > 발동한다. 규칙을 끈 상태에서 취약화하면 그 전환 이벤트가 사라지고, 나중에 규칙을
  > 다시 켜도 **재생(replay)되지 않는다**(이미 NON_COMPLIANT 로 "머물러" 있어 새 전환이
  > 없음). 규칙을 켠 채로 flip 하면 전환 이벤트가 곧바로 Lambda 를 호출한다.

- **NON_COMPLIANT 로 멈춰 있는데 조치가 안 돌 때** (규칙을 껐다 켜서 전환을 놓친 경우):
  규칙을 켠 채로 **COMPLIANT 로 한 번 되돌렸다가 다시 취약화**해 새 전환을 만든다.
  ```bash
  B=$(terraform output -raw vulnerable_bucket)
  R=$(terraform output -raw config_rule_name)
  # 1) COMPLIANT 로 (BPA 켜기) → 전환의 출발점
  aws s3api put-public-access-block --bucket $B --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
  aws configservice start-config-rules-evaluation --config-rule-names $R   # COMPLIANT 확인
  # 2) 다시 취약화(BPA 끄기) → COMPLIANT→NON_COMPLIANT 전환 → EventBridge → Lambda 조치
  aws s3api put-public-access-block --bucket $B --public-access-block-configuration \
    BlockPublicAcls=false,IgnorePublicAcls=false,BlockPublicPolicy=false,RestrictPublicBuckets=false
  aws configservice start-config-rules-evaluation --config-rule-names $R
  ```

- **완전 정리**:
  ```bash
  terraform destroy
  ```
  Config 버킷/취약 버킷은 `force_destroy = true` 라 객체까지 함께 삭제된다.

---

## 7. 트러블슈팅

| 증상 | 확인 |
|------|------|
| 규칙이 계속 평가 안 됨 | Config **Recorder 가 켜짐**인지(2-2). 기존 Config 있는 계정이면 `manage_config_baseline=false` 로 두고 재배포했는지 |
| 리소스가 콘솔에 안 보임 | 우상단 **리전이 서울(ap-northeast-2)** 인지 |
| Lambda 로그가 안 생김 | EventBridge 규칙 대상/`lambda_permission` 확인(2-3). 규칙이 아직 NON_COMPLIANT 가 안 됐을 수도 있음(3) |
| 규칙은 켰는데 NON_COMPLIANT 인 채 조치가 안 돎 | 규칙을 껐다 켜서 **전환 이벤트를 놓친** 경우. EventBridge 는 상태가 아니라 *전환*에만 발동 → 6번의 "멈춰 있을 때" 절차로 새 전환 생성. Lambda 자체 확인은 `aws lambda invoke` 직접 호출 |
| `status=error` 로그 | `error_type/error` 확인. 보통 권한(대상 버킷 ARN 밖) 또는 버킷 삭제됨 |
| `apply` 가 recorder 중복으로 실패 | 계정에 이미 Config Recorder 존재 → `manage_config_baseline=false` |

---

관련 문서: 조치 상세·CLI 절차는 [`../runbooks/s3-public-access.md`](../runbooks/s3-public-access.md).
