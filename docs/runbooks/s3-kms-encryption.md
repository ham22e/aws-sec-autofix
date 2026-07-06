# 런북 — S3 저장 데이터 암호화 (KMS)

이 런북은 조치 함수 `lambda/s3-kms-encryption/handler.py` 와 1:1로 짝을 이룬다.
탐지 규칙, 자동 조치 동작, 사람이 직접 조치·검증하는 절차를 담는다.

> 미암호화 리소스 시나리오 3종 중 **"제자리 암호화가 가능한"** 경우다. 세 리소스의
> 조치 스펙트럼은 [`ebs-encryption-default.md`](ebs-encryption-default.md),
> [`rds-storage-encryption.md`](rds-storage-encryption.md) 와 함께 본다.

---

## 1. 통제 항목

| 항목 | 값 |
|------|-----|
| 통제 ID | `s3-kms-encryption` |
| 탐지 규칙 | AWS Config 관리형 규칙 `S3_DEFAULT_ENCRYPTION_KMS` |
| 위반 상태 | 버킷 기본 암호화가 KMS(SSE-KMS/DSSE-KMS)가 아님 → `NON_COMPLIANT` |
| 심각도 | 중간 (저장 데이터 암호화 강도·키 관리 통제 미흡) |
| 조치 방식 | 자동 (EventBridge → Lambda), 비파괴 |
| 트리거 | **구성 변경(Configuration change)** |

### 무엇이 위반인가
`S3_DEFAULT_ENCRYPTION_KMS` 는 버킷이 **KMS 키로 암호화되는지**를 본다. 2023-01 이후
모든 S3 버킷은 기본적으로 SSE-S3(AES256)로 암호화되지만, 이 규칙은 **SSE-S3 만으로는
NON_COMPLIANT** 로 본다(KMS 요구). 즉 "암호화가 아예 없어서"가 아니라 "KMS 가 아니라서"
위반이다. 테스트 버킷은 SSE-S3(AES256)를 명시 고정해 이 상태를 재현한다.

> 이 규칙은 계정의 모든 버킷을 평가할 수 있으나, 조치 대상과 blast radius 를 테스트
> 버킷 하나로 한정하기 위해 Terraform 에서 규칙 scope 를 그 버킷으로 좁혀 두었다.

---

## 2. 자동 조치 흐름

```
취약 버킷(SSE-S3=AES256 만)
  → Config 규칙 평가 = NON_COMPLIANT
  → EventBridge 규칙(compliance change 필터) 매칭
  → 조치 Lambda 호출
  → put_bucket_encryption 으로 SSE-KMS(고객관리형 키, BucketKeyEnabled) 적용
  → Config 재평가 = COMPLIANT
```

**핵심: 조치 자체가 "버킷 암호화 구성 변경"이다.** 그래서 Config 가 그 변경을 감지해
규칙을 **자동 재평가**하고 COMPLIANT 로 닫는다(강제 평가 불필요 — S3 는 변경 트리거).

### 조치 함수 동작
- **멱등적**: `get_bucket_encryption` 으로 현재 상태를 확인해, 이미 대상 KMS 키로
  SSE-KMS 면 아무것도 바꾸지 않고 `status="already_compliant"`.
- **비파괴적**: 버킷 기본 암호화 설정만 바꾼다. 버킷·객체를 삭제하지 않는다.
  ⚠️ **기존 객체는 재암호화되지 않는다.** 기본 암호화는 **신규 객체**부터 KMS 로
  적용된다. 이미 저장된 객체를 KMS 로 소급 암호화하려면 별도 copy(아래 5번)가 필요하다.
- **관측 가능**: 결과를 JSON 한 줄 구조화 로그로 남긴다. 예:
  ```json
  {"bucket":"autofix-unencrypted-abc123","control":"s3-kms-encryption","event_type":"remediation","kms_key":"arn:aws:kms:ap-northeast-2:...:key/...","previous_kms_key":null,"status":"applied","timestamp":"..."}
  ```
- **상태값**: `applied` / `already_compliant` / `skipped`(이벤트에 버킷 없음) / `error`.

로그는 `/aws/lambda/<project_name>-s3-kms-encryption` 로그 그룹에 쌓인다.

> ⚠️ **트리거는 "전환"이다.** EventBridge 규칙은 컴플라이언스가 바뀌는 순간에만
> 발동한다(S3 퍼블릭 노출 시나리오와 동일). 재현이 안 될 때는 규칙을 켠 채로 COMPLIANT →
> NON_COMPLIANT 전환을 새로 만든다.

---

## 3. 수동 조치 절차 (자동 조치가 실패하거나 임시 대응이 필요할 때)

### 콘솔
1. S3 → 대상 버킷 → **속성(Properties)** → **기본 암호화(Default encryption)** → 편집.
2. **AWS KMS 키(SSE-KMS)** 선택 → 대상 KMS 키(`alias/<project_name>-s3`) 지정 →
   **버킷 키(Bucket Key)** 활성화 → 저장.

### CLI
```bash
aws s3api put-bucket-encryption \
  --bucket <BUCKET> \
  --server-side-encryption-configuration '{
    "Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms","KMSMasterKeyID":"<KMS_KEY_ARN>"},"BucketKeyEnabled":true}]
  }'
```

### 기존 객체까지 KMS 로 소급 암호화 (선택, 신중히)
기본 암호화 변경은 신규 객체에만 적용되므로, 기존 객체를 KMS 로 바꾸려면 재작성이 필요하다.
```bash
# 같은 키로 in-place copy → KMS 로 재암호화 (객체 메타·버전 영향 주의)
aws s3 cp s3://<BUCKET>/ s3://<BUCKET>/ --recursive \
  --sse aws:kms --sse-kms-key-id <KMS_KEY_ARN>
```
> ⚠️ 버전 관리·객체 메타데이터·수명주기에 영향을 줄 수 있어 운영 버킷에서는 승인·계획 후 수행.

---

## 4. 검증

```bash
# 1) 버킷 기본 암호화가 aws:kms 인지 확인
aws s3api get-bucket-encryption --bucket <BUCKET>

# 2) (선택) 규칙 재평가 트리거 — S3 는 변경 트리거라 보통 자동이지만 즉시 확인용
aws configservice start-config-rules-evaluation \
  --config-rule-names <project_name>-s3-default-encryption-kms

# 3) 규칙이 COMPLIANT 로 바뀌었는지 확인
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name <project_name>-s3-default-encryption-kms \
  --compliance-types COMPLIANT
```

CloudWatch Logs 에서 조치 로그(`status=applied`)를 함께 확인한다.

---

## 5. 롤백 · 예외 처리

- **롤백(가역)**: 버킷 기본 암호화를 SSE-S3 로 되돌리면 다시 NON_COMPLIANT 가 된다.
  ```bash
  aws s3api put-bucket-encryption --bucket <BUCKET> \
    --server-side-encryption-configuration '{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"AES256"}}]}'
  ```
- **조치 실패(`status=error`)**: 로그의 `error_type`/`error` 확인. 흔한 원인은 권한 부족
  (역할에 대상 버킷 ARN·키 ARN 이 없음) 또는 키 정책 문제.

---

## 6. KMS 키 lifecycle 주의

- 조치가 적용하는 키는 **고객관리형 KMS 키**다. `terraform destroy` 시 키는 즉시
  삭제되지 않고 **삭제 대기(기본 이 테스트 7일)** 상태로 들어간다(별칭은 즉시 해제).
  대기 중 키는 사실상 과금이 없지만, 계정에 "PendingDeletion" 키가 잠시 남는다.
- 즉시 정리하려면 콘솔/`aws kms schedule-key-deletion` 으로 확인하되, 최소 대기(7일)는
  AWS 제약이라 우회할 수 없다.

---

## 7. Terraform 드리프트 주의

취약 버킷의 기본 암호화(SSE-S3)는 Terraform 이 관리한다. 조치 Lambda 가 이를 KMS 로
바꾸면 상태와 실제가 어긋난다.
- 조치 후 `terraform plan` 에 암호화 설정 드리프트가 뜨는 것은 정상이다.
- `terraform apply` 하면 다시 취약(SSE-S3) 상태로 리셋된다 → 재검증에 활용.

---

## 8. 참고
- 규칙 세부: https://docs.aws.amazon.com/config/latest/developerguide/s3-default-encryption-kms.html
- S3 기본 암호화: https://docs.aws.amazon.com/AmazonS3/latest/userguide/default-bucket-encryption.html
- S3 버킷 키(비용 절감): https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-key.html
