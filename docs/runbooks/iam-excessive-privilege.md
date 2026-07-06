# 런북 — IAM 과도 권한 (IAM Excessive Privilege / CIEM)

이 런북은 조치 함수 두 개와 1:1로 짝을 이룬다.
- 탐지·알림: `lambda/iam-excessive-privilege/detect-notify/handler.py`
- 승인 조치: `lambda/iam-excessive-privilege/approve-remediate/handler.py`

S3 시나리오와의 결정적 차이는 **자동 조치를 하지 않는다**는 점이다. 탐지·알림은
자동이지만, 실제 권한 변경은 **사람이 승인**할 때만 일어난다. 그 이유를 먼저 남긴다.

---

## 1. 통제 항목

| 항목 | 값 |
|------|-----|
| 통제 ID | `iam-excessive-privilege` |
| 탐지 규칙 | AWS Config 관리형 규칙 `IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS` |
| 위반 상태 | 고객관리형 정책 기본 버전에 `Action:"*"` + `Resource:"*"` 허용 → `NON_COMPLIANT` |
| 심각도 | 높음 (권한 상승·광범위한 침해 경로) |
| 조치 방식 | **승인 기반(수동)** — 자동 조치하지 않음. 알림만 자동, 조치는 사람 승인 후 |

### 무엇이 위반인가
`IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS` 는 **고객관리형 정책의 "기본 버전"** 만
평가한다(인라인 정책·AWS 관리형 정책은 평가하지 않는다). 어떤 문(statement)이
`"Effect":"Allow"` 이면서 `"Action":"*"` 를 `"Resource":"*"` 에 허용하면
`NON_COMPLIANT` 가 된다.

> ⚠️ **규칙은 "정책 문서"를 본다 — "부착 관계"가 아니다.** 그래서 정책을 역할에서
> **detach 만 해서는 규칙이 COMPLIANT 로 바뀌지 않는다.** 정책 문서 자체에서 admin
> 문을 제거(= 기본 버전 교체)해야 COMPLIANT 가 된다. (3, 4번 참고)

---

## 2. 왜 자동 조치하지 않는가 (핵심 근거)

S3 퍼블릭 노출은 자동으로 차단(BPA 켜기)했지만, IAM 과도 권한은 **자동으로
회수하지 않는다.** 이유:

1. **되돌릴 수 없는 다운타임.** IAM 권한을 자동으로 회수/축소하면 그 권한에
   의존하던 **정당한 워크로드·운영자의 접근이 즉시 끊긴다.** S3 노출 차단은 데이터를
   지우지 않는 "차단"이라 가역적이지만, 권한 회수는 장애가 먼저 나고 복구가 뒤따르는
   구조라 사실상 **self-inflicted DoS** 가 될 수 있다.
2. **오탐 비용의 비대칭.** 퍼블릭 버킷 오탐 조치는 되돌리기 쉽지만, 광범위하게 쓰이는
   역할의 권한을 잘못 회수하면 영향 범위가 크고 복구 비용이 높다.
3. **CIEM 실무 흐름.** 권한 축소(least-privilege rightsizing)는 "관찰 → 제안 →
   **승인** → 적용"의 점진적 과정이다. 자동 차단이 아니라 **승인 게이트**를 두는 것이
   실무 표준에 부합한다.

그래서 이 시나리오는 **탐지·알림은 자동, 조치는 승인 기반**으로 설계했다.
탐지 Lambda 에는 정책을 바꿀 권한 자체가 없다(SNS 발행 + 읽기 전용).

---

## 3. 탐지·알림 흐름 (자동)

```
과도 권한 정책(Action:* Resource:*, 더미 역할에 부착)
  → Config 규칙 평가 = NON_COMPLIANT
  → EventBridge 규칙(compliance change 필터) 매칭
  → 탐지·알림 Lambda 호출
  → SNS 알림 발행 (대상 정책·부착 주체·승인 방법 안내)  ← 여기서 자동 처리 끝
  → (정책은 변경되지 않음)
```

### 탐지 Lambda 동작
- **비파괴**: 어떤 정책·역할도 변경하지 않는다. `sns:Publish` 로 알림만 보낸다.
- **영향 범위 표기**: Config 이벤트는 정책 **ID** 만 주므로, 배포 시점에 아는 테스트
  정책 ARN(환경변수 `VULNERABLE_POLICY_ARN`)으로 `iam:ListEntitiesForPolicy` 를 호출해
  "이 admin 정책이 어떤 역할·사용자·그룹에 부착됐는지"를 알림에 담는다. 조회 실패는
  알림을 막지 않고 축약 처리한다.
- **관측 가능**: 결과를 JSON 한 줄 구조화 로그로 남긴다. 상태값:
  `notified`(알림 발송) / `skipped`(이벤트에 리소스 없음) / `error`.

로그는 `/aws/lambda/<project_name>-iam-detect-notify` 로그 그룹에 쌓인다.

> ⚠️ **트리거는 "전환"이다.** EventBridge 규칙은 컴플라이언스가 **바뀌는 순간**
> (`COMPLIANT → NON_COMPLIANT`)에만 발동한다. 규칙을 끈 채 취약 정책을 만들면 전환
> 이벤트를 잃고, 규칙을 다시 켜도 재생되지 않는다. 재현이 안 되면 규칙을 켠 채로
> 전환을 새로 만든다(예: 정책을 COMPLIANT 로 돌린 뒤 다시 admin 으로 되돌리기).

---

## 4. 승인 기반 조치 절차 (사람이 승인)

승인 조치 Lambda(`<project_name>-iam-approve-remediate`)는 **EventBridge 에 연결돼
있지 않다.** 운영자가 알림을 검토한 뒤 **직접 invoke** 해야만 조치한다.

### 조치가 하는 일 (라이트사이징)
대상 정책의 **기본 버전을 최소 권한 문서로 교체**한다
(`CreatePolicyVersion` + `SetAsDefault=true`). 규칙이 "기본 버전"을 평가하므로 이렇게
해야 COMPLIANT 로 전환된다. **기존 버전은 삭제하지 않아 되돌릴 수 있다(가역).**
`payload` 에 `replacement_document` 를 주면 그 정책을, 없으면 문서화된 최소 권한
기본값(`sts:GetCallerIdentity` 만 허용)을 적용한다.

### CLI (권장)
```bash
# 1) 승인 조치 실행 (confirm:true 필수 — 승인 게이트)
#    AWS CLI v2 는 JSON payload 전달 시 --cli-binary-format 이 필요하다.
aws lambda invoke \
  --function-name <project_name>-iam-approve-remediate \
  --cli-binary-format raw-in-base64-out \
  --payload '{"policy_arn":"<ADMIN_POLICY_ARN>","confirm":true}' \
  out.json
cat out.json     # {"status":"applied","new_default_version":"vN"} 확인
```

- `confirm` 을 빼거나 `true` 가 아니면 **아무것도 바꾸지 않고** `rejected_no_confirmation`
  을 반환한다(승인 게이트).
- `policy_arn` 을 생략하면 환경변수의 테스트 정책(`DEFAULT_POLICY_ARN`)을 대상으로 한다.
- 이미 admin 이 아니면 `already_remediated`(멱등).

### 콘솔 등가 절차
1. IAM → **정책(Policies)** → 대상 정책 → **정책 버전(Policy versions)** 탭.
2. **새 버전 생성** → 최소 권한 문서 작성 → **기본 버전으로 설정** 저장.
3. (선택) 광범위 접근을 즉시 줄이려면 **역할에서 정책 분리(detach)** 도 병행.
   단, detach 만으로는 **Config 규칙이 COMPLIANT 로 바뀌지 않는다**(2번 경고 참고).

---

## 5. 검증

```bash
# 1) 조치 후 정책 기본 버전이 비-admin 인지 확인
aws iam get-policy --policy-arn <ADMIN_POLICY_ARN>          # DefaultVersionId 확인
aws iam get-policy-version \
  --policy-arn <ADMIN_POLICY_ARN> --version-id <DefaultVersionId>

# 2) Config 규칙 재평가 트리거(선택, 즉시 확인하고 싶을 때)
aws configservice start-config-rules-evaluation \
  --config-rule-names <project_name>-iam-policy-no-admin-access

# 3) 규칙이 COMPLIANT 로 바뀌었는지 확인
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name <project_name>-iam-policy-no-admin-access \
  --compliance-types COMPLIANT
```

CloudWatch Logs 에서 조치 로그(`status=applied`)와 탐지 로그(`status=notified`)를
함께 확인한다.

---

## 6. 롤백 · 예외 처리

- **롤백(가역)**: 조치는 기존 버전을 지우지 않고 새 버전을 기본으로 지정할 뿐이다.
  원복하려면 이전 버전을 다시 기본으로 지정한다:
  ```bash
  aws iam list-policy-versions --policy-arn <ADMIN_POLICY_ARN>
  aws iam set-default-policy-version \
    --policy-arn <ADMIN_POLICY_ARN> --version-id <이전 버전 예: v1>
  ```
  (원복하면 다시 admin 이 되어 규칙은 NON_COMPLIANT 로 돌아간다 = 재검증에 활용.)
- **버전 상한**: IAM 은 정책당 버전 5개 제한. 조치 함수는 가득 차면 가장 오래된
  비-기본 버전 1개를 자동 삭제하고 새 버전을 만든다.
- **조치 실패(`status=error`)**: 로그의 `error_type`/`error` 확인. 흔한 원인은 권한
  부족(역할에 대상 정책 ARN 이 없음) 또는 정책이 이미 삭제됨.
- **교체 문서가 admin 인 경우**: `replacement_document` 자체가 `Action:*`+`Resource:*`
  이면 조치해도 COMPLIANT 가 안 되므로 함수가 `rejected_replacement_has_admin` 으로 거부한다.

---

## 7. 전제 — 글로벌 리소스 기록

IAM 은 **글로벌 리소스**다. 이 규칙이 평가되려면 Config Recorder 가 IAM 리소스를
기록해야 한다. `terraform/modules/config-baseline` 에서
`recording_group.include_global_resource_types = true` 로 켜 두었다.

- 이 번들 옵션은 **2022-02 이전에 Config 가 제공된 리전에서만** 글로벌 IAM 리소스를
  기록한다. 서울(ap-northeast-2)은 해당되어 정상 동작한다.
- 글로벌 리소스는 중복 기록을 피하려고 계정 내 **한 리전에서만** 켜는 것을 권장한다.
- 이 옵션을 켜면 Config 가 IAM 리소스까지 추적해 기록 항목이 늘고 요금이 소폭 증가한다
  (테스트 계정은 미미).

---

## 8. Terraform 드리프트 주의

취약 정책의 admin 기본 버전은 Terraform 이 관리한다. 승인 조치 Lambda 가 기본 버전을
바꾸면 Terraform 상태와 실제가 어긋난다.

- 조치 후 `terraform plan` 에 **정책 버전 드리프트가 뜨는 것은 정상**이다.
- `terraform apply` 하면 정책이 다시 취약(admin) 상태로 리셋된다 → **재검증에 활용**.
- 드리프트를 무시하려면 `lifecycle { ignore_changes = [...] }` 를 쓸 수 있지만, 재검증
  편의를 위해 현재는 사용하지 않는다.

---

## 9. 참고
- 규칙 세부: https://docs.aws.amazon.com/config/latest/developerguide/iam-policy-no-statements-with-admin-access.html
- 정책 버전: https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_managed-versioning.html
- Config 글로벌 리소스 기록: https://docs.aws.amazon.com/config/latest/developerguide/select-resources.html
