# 런북 — S3 퍼블릭 노출 (S3 Public Read)

이 런북은 조치 함수 `lambda/s3-public-access/handler.py` 와 1:1로 짝을 이룬다.
탐지 규칙, 자동 조치 동작, 사람이 직접 조치·검증하는 절차를 담는다.

---

## 1. 통제 항목

| 항목 | 값 |
|------|-----|
| 통제 ID | `s3-public-access` |
| 탐지 규칙 | AWS Config 관리형 규칙 `S3_BUCKET_PUBLIC_READ_PROHIBITED` |
| 위반 상태 | 버킷이 퍼블릭 read 를 허용 → `NON_COMPLIANT` |
| 심각도 | 높음 (데이터 유출 직접 경로) |
| 조치 방식 | 자동 (EventBridge → Lambda), 비파괴 |

### 무엇이 위반인가
`S3_BUCKET_PUBLIC_READ_PROHIBITED` 는 Block Public Access(BPA) 설정 + 버킷 정책 +
ACL 을 함께 평가한다. **BPA 가 퍼블릭 정책/ACL 을 막지 않고, 정책이나 ACL 이
퍼블릭 read(`Principal:"*"`, `s3:GetObject`)를 허용**하면 `NON_COMPLIANT` 가 된다.
즉 BPA 해제만으로는 위반이 아니며, 퍼블릭 정책/ACL 이 함께 있어야 한다.

---

## 2. 자동 조치 흐름

```
취약 버킷(BPA 4종 off + 퍼블릭 read 정책)
  → Config 규칙 평가 = NON_COMPLIANT
  → EventBridge 규칙(compliance change 필터) 매칭
  → 조치 Lambda 호출
  → put_public_access_block 으로 BPA 4종 강제 적용
  → Config 재평가 = COMPLIANT
```

### 조치 함수 동작
- **멱등적**: 조치 전 `get_public_access_block` 으로 현재 상태를 확인해, 이미 4종이
  켜져 있으면 아무것도 바꾸지 않고 `status="already_compliant"` 로 기록한다.
- **비파괴적**: BPA 4종만 켠다. 버킷·객체·**버킷 정책을 삭제하지 않는다.**
  BPA(`BlockPublicPolicy`, `RestrictPublicBuckets`)가 켜지면 퍼블릭 정책이 그대로
  있어도 S3 가 퍼블릭 접근을 차단하므로, 노출만 막고 원인 정책은 보존된다.
- **관측 가능**: 결과를 JSON 한 줄 구조화 로그로 남긴다. 예:
  ```json
  {"applied":{"BlockPublicAcls":true,"BlockPublicPolicy":true,"IgnorePublicAcls":true,"RestrictPublicBuckets":true},"bucket":"autofix-public-abc123","compliance_before":"NON_COMPLIANT","control":"s3-public-access","event_type":"remediation","status":"applied","timestamp":"..."}
  ```
- **상태값**: `applied`(조치함) / `already_compliant`(이미 안전) / `skipped`(이벤트에
  버킷 없음) / `error`(조치 실패, 예외 재전파).

로그는 `/aws/lambda/<project_name>-s3-remediation` 로그 그룹에 쌓인다.

> ⚠️ **트리거는 "전환"이다.** EventBridge 규칙은 컴플라이언스가 **바뀌는 순간**
> (`COMPLIANT → NON_COMPLIANT`)에만 발동하며, 이미 NON_COMPLIANT 로 머물러 있는
> 상태에는 반응하지 않는다. 그래서 규칙을 **끈 채로** 취약화하면 전환 이벤트를 잃고,
> 규칙을 다시 켜도 재생되지 않는다. 재현·조치가 안 될 때는 규칙을 켠 채로
> COMPLIANT → NON_COMPLIANT 전환을 새로 만든다(가이드 6번 참고).

---

## 3. 수동 조치 절차 (자동 조치가 실패하거나 임시 대응이 필요할 때)

### 콘솔
1. S3 → 대상 버킷 → **권한(Permissions)** 탭.
2. **퍼블릭 액세스 차단(Block public access)** → 편집 → **4종 모두 체크(켜기)** → 저장.
3. (필요 시) 아래 **버킷 정책**의 퍼블릭 허용 문을 검토·제거.

### CLI
```bash
# BPA 4종 강제 적용 (조치 Lambda 와 동일 동작, 비파괴)
aws s3api put-public-access-block \
  --bucket <BUCKET> \
  --public-access-block-configuration \
    BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true
```

> 원인이 된 퍼블릭 버킷 정책까지 완전히 제거하려면(파괴적, 승인 필요):
> `aws s3api delete-bucket-policy --bucket <BUCKET>`

---

## 4. 검증

```bash
# 1) BPA 4종이 모두 true 인지 확인
aws s3api get-public-access-block --bucket <BUCKET>

# 2) Config 규칙 재평가 트리거(선택, 즉시 확인하고 싶을 때)
aws configservice start-config-rules-evaluation \
  --config-rule-names <project_name>-s3-bucket-public-read-prohibited

# 3) 규칙이 COMPLIANT 로 바뀌었는지 확인
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name <project_name>-s3-bucket-public-read-prohibited \
  --compliance-types COMPLIANT
```

CloudWatch Logs 에서 조치 로그(`status=applied`)를 함께 확인한다.

---

## 5. 롤백 · 예외 처리

- **롤백**: 이 조치는 "노출 차단"이므로 정상 롤백 대상이 아니다. 특정 버킷을 의도적으로
  퍼블릭으로 둬야 한다면(예: 정적 웹 호스팅), 그 버킷을 조치 대상에서 **제외**하는 것이
  옳다. 현재 Lambda 는 IAM 으로 테스트 취약 버킷 ARN 에만 권한이 있어 다른 버킷은 조치하지
  못한다. 대상 확대 시에는 예외 목록(allowlist) 설계를 함께 한다.
- **조치 실패(`status=error`)**: 로그의 `error_type`/`error` 확인. 흔한 원인은 권한 부족
  (역할에 대상 버킷 ARN 이 없음) 또는 버킷이 이미 삭제됨.

---

## 6. Terraform 드리프트 주의

취약 버킷의 BPA(4종 off)는 Terraform 이 관리한다. 조치 Lambda 가 이를 4종 on 으로
바꾸면 Terraform 상태와 실제가 어긋난다.

- 조치 후 `terraform plan` 에 **BPA 드리프트가 뜨는 것은 정상**이다.
- `terraform apply` 하면 버킷이 다시 취약(BPA off) 상태로 리셋된다 → **재검증에 활용**.
- 드리프트를 무시하고 조치 상태를 유지하려면 `aws_s3_bucket_public_access_block` 에
  `lifecycle { ignore_changes = [...] }` 를 추가하면 되지만, 재검증 편의를 위해
  현재는 사용하지 않는다.

---

## 7. 참고
- 규칙 세부: https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-public-read-prohibited.html
- BPA 개념: https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html
