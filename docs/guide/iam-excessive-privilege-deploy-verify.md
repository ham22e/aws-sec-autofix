# 배포 & 검증 가이드 — IAM 과도 권한

`terraform apply` 로 배포한 뒤, **탐지 → 자동 알림 → (사람 승인) → 조치 → `COMPLIANT`**
한 사이클을 확인하는 절차다.

> **S3 시나리오와 결정적 차이**: IAM 은 **자동 조치하지 않는다.** 탐지·알림까지만
> 자동이고, 실제 권한 변경은 사람이 **승인 조치 Lambda 를 수동 invoke** 할 때만
> 일어난다. 왜 그런지는 `docs/runbooks/iam-excessive-privilege.md` 2절 참고.

> 리전: **ap-northeast-2 (서울)**. 콘솔 우상단 리전이 서울인지 먼저 확인한다.

리소스 이름은 `project_name`(기본 `autofix`) 접두사를 쓴다.

| 리소스 | 이름(기본값) |
|--------|--------------|
| 취약 admin 정책 | `autofix-admin-<임의suffix>` |
| 더미(과도 권한) 역할 | `autofix-overprivileged-<임의suffix>` |
| Config 규칙 | `autofix-iam-policy-no-admin-access` |
| EventBridge 규칙 | `autofix-iam-admin-noncompliant` |
| 탐지·알림 Lambda | `autofix-iam-detect-notify` |
| 승인 조치 Lambda | `autofix-iam-approve-remediate` |
| SNS 토픽 | `autofix-iam-alerts` |
| 탐지 로그 그룹 | `/aws/lambda/autofix-iam-detect-notify` |
| 조치 로그 그룹 | `/aws/lambda/autofix-iam-approve-remediate` |

---

## 0. 사전 준비

1. `terraform/terraform.tfvars` 에 배포 프로필 지정(예: `aws_profile = "내프로필"`).
2. (선택) SNS **이메일 알림**을 받으려면 `terraform.tfvars` 에 `alert_email` 지정.
   지정하지 않으면 토픽만 만들어지고, 탐지는 **Lambda 로그**로 확인한다(3-2).
3. 배포 권한 부여 — `docs/deploy-iam-policy.json` 또는 (격리 계정이면) `AdministratorAccess`.
4. 자격증명 확인:
   ```bash
   AWS_PROFILE=<프로필> aws sts get-caller-identity
   ```

> **전제**: IAM 은 글로벌 리소스라, Config Recorder 가 IAM 을 기록해야 규칙이 평가된다.
> 이 스택은 `config-baseline` 에서 글로벌 리소스 기록을 켜 둔다(코드 상수). 이 옵션은
> 2022-02 이전에 Config 가 제공된 리전에서만 동작하며, 서울은 해당된다.

---

## 1. 배포 (terraform apply)

```bash
cd terraform
terraform plan      # 생성될 리소스 검토 (전부 신규 생성이어야 함)
terraform apply     # yes 입력
```

`apply` 후 출력에서 실제 이름/ARN 을 확인한다:
```bash
terraform output
# iam_vulnerable_policy_arn    = "arn:aws:iam::<account>:policy/autofix-admin-xxxx"
# iam_config_rule_name         = "autofix-iam-policy-no-admin-access"
# iam_detect_notify_lambda     = "autofix-iam-detect-notify"
# iam_approve_remediate_lambda = "autofix-iam-approve-remediate"
# iam_sns_topic_arn            = "arn:aws:sns:ap-northeast-2:<account>:autofix-iam-alerts"
```

> ⚠️ `apply` 직후 admin 정책은 **실제로 과도 권한(`*:*`)이 부여된 상태**다. 격리 테스트
> 계정에서만 진행하고, 끝나면 `terraform destroy` 한다.

### (alert_email 지정한 경우) 이메일 구독 확인
배포 후 해당 주소로 **"AWS Notification - Subscription Confirmation"** 메일이 온다.
메일의 **Confirm subscription** 링크를 눌러야 실제로 알림을 받는다.

> ⚠️ **구독 확인 타이밍 함정.** SNS 는 구독이 **확인되기 전에** 발행된 메시지는
> 전달하지 않고 버린다(재전송도 안 함). `apply` 직후 탐지가 몇 초 만에 뜨면, 그 순간
> 구독이 아직 미확인이라 **첫 알림이 유실**될 수 있다. 이땐 메일이 안 온 게 정상이며,
> 구독을 확인한 뒤 **새 탐지를 한 번 유발**하면(정책을 COMPLIANT→다시 admin 으로 전환,
> 또는 탐지 Lambda 재호출) 메일이 도착한다.
> (S3 시나리오의 "전환 이벤트 유실"과 같은 종류의 타이밍 이슈다.)

---

## 2. 배포 리소스 확인 (콘솔)

### 2-1. 취약 admin 정책
- **IAM → 정책(Policies) →** `autofix-admin-...` 클릭.
- **{ } JSON** 탭에 `"Action": "*"`, `"Resource": "*"` 문 확인.
- **사용 중(Entities attached)** 에 더미 역할 `autofix-overprivileged-...` 부착 확인.
- 태그에 `Purpose = intentionally-vulnerable` 확인.

### 2-2. AWS Config
- **AWS Config → 설정(Settings)** 에서 Recorder **켜짐(Recording is on)** 확인.
  - **기록할 리소스(Resource types)** 에 **글로벌 리소스 포함** 여부가 켜져 있는지 확인.
- **규칙(Rules) →** `autofix-iam-policy-no-admin-access` 존재 확인.

### 2-3. 연결 확인 (자동 경로 vs 승인 경로)
- **EventBridge → 규칙 →** `autofix-iam-admin-noncompliant`
  → **대상**이 **탐지·알림 Lambda**(`...-iam-detect-notify`)인지 확인.
- **Lambda →** `...-iam-detect-notify` → **트리거**에 EventBridge 연결 확인(자동 경로).
- **Lambda →** `...-iam-approve-remediate` → **트리거가 "없음"** 인지 확인.
  → 승인 조치는 자동으로 돌지 않는다(의도된 설계 = 승인 게이트).

---

## 3. 탐지 & 알림 확인 (자동)

Config 최초 평가는 **수 분** 걸릴 수 있다. 즉시 보려면 강제 재평가한다.

### 3-1. NON_COMPLIANT (Config 콘솔)
- **AWS Config → 규칙 →** 해당 규칙 클릭. 바로 안 뜨면 **작업 → 재평가** 후 새로고침.
- 상태가 **`NON_COMPLIANT`**, 범위 내 리소스에 admin 정책이 뜨면 탐지 성공.

### 3-2. 알림 발송 (탐지 Lambda 로그 / SNS)
- **CloudWatch → 로그 그룹 →** `/aws/lambda/autofix-iam-detect-notify`
  최신 스트림에서 **JSON 한 줄** 로그 확인:
  ```json
  {"attached_entities":{"groups":[],"roles":["autofix-overprivileged-xxxx"],"users":[]},"compliance":"NON_COMPLIANT","control":"iam-excessive-privilege","event_type":"remediation","policy_id":"ANPA...","status":"notified","timestamp":"...","topic":"arn:aws:sns:..."}
  ```
  - `status=notified` = 알림 발송됨. **정책은 변경되지 않았다.**
- `alert_email` 을 지정하고 구독을 확인했다면, 같은 내용의 **알림 메일**이 도착한다
  (대상 정책 ID·부착 주체·승인 방법 안내 포함).

> ⚠️ 이 규칙은 계정의 **모든 고객관리형 정책**을 평가한다. 테스트 계정에 다른 admin
> 정책이 이미 있으면 그것도 함께 `NON_COMPLIANT` 로 잡힌다(격리 계정 권장).

---

## 4. 승인 기반 조치 (사람이 승인)

알림을 검토했다면, 이제 **직접** 승인 조치 Lambda 를 invoke 한다. 이것이 승인 게이트다.

```bash
FN=$(terraform output -raw iam_approve_remediate_lambda)

# confirm:true 가 있어야만 조치한다. (AWS CLI v2 는 --cli-binary-format 필요)
aws lambda invoke --function-name "$FN" \
  --cli-binary-format raw-in-base64-out \
  --payload '{"confirm":true}' out.json    # policy_arn 생략 시 테스트 정책 대상
cat out.json    # {"status":"applied","new_default_version":"vN", ...}
```

- `confirm` 없이/`false` 로 부르면 **아무것도 바꾸지 않고** `rejected_no_confirmation` 반환.
- 특정 정책을 지정하려면: `--payload "{\"policy_arn\":\"$(terraform output -raw iam_vulnerable_policy_arn)\",\"confirm\":true}"`
- 이미 조치됐으면 `already_remediated`(멱등).

### 조치 로그 확인
- **CloudWatch → 로그 그룹 →** `/aws/lambda/autofix-iam-approve-remediate`
  ```json
  {"control":"iam-excessive-privilege","event_type":"remediation","new_default_version":"v2","policy_arn":"arn:aws:iam::...:policy/autofix-admin-xxxx","previous_default_version":"v1","status":"applied","timestamp":"..."}
  ```

### 정책이 라이트사이징됐는지 (IAM 콘솔/CLI)
```bash
ARN=$(terraform output -raw iam_vulnerable_policy_arn)
DV=$(aws iam get-policy --policy-arn "$ARN" --query 'Policy.DefaultVersionId' --output text)
aws iam get-policy-version --policy-arn "$ARN" --version-id "$DV"
# 새 기본 버전에 Action:* / Resource:* 가 없어야 한다(최소 권한으로 교체됨).
```
- IAM 콘솔: 정책 → **정책 버전** 탭에 새 버전이 **기본(Default)** 으로 표시.
- **구 버전은 그대로 남아 있다** → 되돌리기 가능(6절).

---

## 5. COMPLIANT 전환 확인 (Config 콘솔)

- 기본 버전이 바뀌면 그 구성 변경으로 Config 가 **자동 재평가**한다.
- **AWS Config → 규칙 →** 해당 규칙이 **`COMPLIANT`** 로 바뀌면 한 사이클 완료.
- 즉시 보려면 강제 재평가:
  ```bash
  aws configservice start-config-rules-evaluation \
    --config-rule-names "$(terraform output -raw iam_config_rule_name)"
  ```

> ⚠️ **detach 만으로는 COMPLIANT 가 되지 않는다.** 규칙은 "정책 문서"를 평가하지
> "부착 관계"를 보지 않는다. 그래서 조치는 역할에서 떼는 게 아니라 **정책 기본 버전을
> 비-admin 으로 교체**한다.

여기까지 오면 **탐지(NON_COMPLIANT) → 자동 알림 → 사람 승인 → 조치 → COMPLIANT**
한 사이클이 재현된 것이다 (DoD 충족).

---

## 6. 롤백 · 재검증 · 정리

### 롤백 (가역 — 조치가 비파괴임을 증명)
조치는 구 버전을 지우지 않으므로 이전 버전을 다시 기본으로 지정하면 원복된다.
```bash
ARN=$(terraform output -raw iam_vulnerable_policy_arn)
aws iam list-policy-versions --policy-arn "$ARN"
aws iam set-default-policy-version --policy-arn "$ARN" --version-id v1   # admin 으로 원복
```
(원복하면 다시 `NON_COMPLIANT` → 알림 → 재검증 흐름을 반복할 수 있다.)

### 다시 취약 상태로 리셋 (Terraform)
승인 조치 후에는 정책 기본 버전이 Terraform 상태와 어긋난다.
```bash
terraform apply   # admin 기본 버전으로 되돌림 → 재검증
```
(조치 후 `terraform plan` 에 정책 버전 드리프트가 뜨는 것은 정상이다.)

> ⚠️ **재검증 시 EventBridge 규칙은 켜둔 채로** 취약화해야 한다. 탐지 알림은
> 컴플라이언스가 **바뀌는 순간**(`COMPLIANT → NON_COMPLIANT` 전환)에만 발동한다.
> 규칙을 끈 채 취약화하면 전환 이벤트를 잃고, 다시 켜도 재생되지 않는다.

### 완전 정리
```bash
terraform destroy
```

---

## 7. 트러블슈팅

| 증상 | 확인 |
|------|------|
| 규칙이 계속 평가 안 됨 | Config **Recorder 켜짐** + **글로벌 리소스 기록 ON** 인지(2-2). IAM 미기록이면 규칙이 평가할 대상이 없다 |
| 리소스가 콘솔에 안 보임 | 우상단 **리전이 서울(ap-northeast-2)** 인지 |
| 이메일 알림이 안 옴 | `alert_email` 지정했는지 + **구독 확인 메일 클릭**했는지(1절). 미지정이면 Lambda 로그로 확인(3-2) |
| 탐지 Lambda 로그가 안 생김 | EventBridge 규칙 대상/권한 확인(2-3). 규칙이 아직 NON_COMPLIANT 가 안 됐을 수도(3-1) |
| `aws lambda invoke` 가 base64 오류 | AWS CLI v2 는 `--cli-binary-format raw-in-base64-out` 필요(4절) |
| 조치했는데 COMPLIANT 안 됨 | detach 만 한 건 아닌지(정책 문서 교체가 필요). 강제 재평가(5절). 교체 문서가 `*:*` 면 `rejected_replacement_has_admin` |
| `status=error` 로그 | `error_type/error` 확인. 보통 권한(대상 정책 ARN 밖) 또는 정책 삭제됨 |
| 다른 정책까지 NON_COMPLIANT | 규칙은 **모든 고객관리형 정책**을 평가한다. 격리 계정에서 진행 |

---

관련 문서: 조치 상세·근거·CLI 절차는 [`../runbooks/iam-excessive-privilege.md`](../runbooks/iam-excessive-privilege.md).
