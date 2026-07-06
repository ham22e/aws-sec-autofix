# 런북 — EBS 저장 데이터 암호화 (계정 기본 암호화)

이 런북은 조치 함수 `lambda/ebs-encryption-default/handler.py` 와 1:1로 짝을 이룬다.
탐지 규칙, 자동 조치(예방) 동작, **기존 볼륨을 왜 자동 조치하지 않는지**와 그 수동 교정
절차를 담는다.

> 미암호화 리소스 시나리오 3종 중 **"제자리 암호화가 불가능한"** 경우다. 세 리소스의
> 조치 스펙트럼은 [`s3-kms-encryption.md`](s3-kms-encryption.md),
> [`rds-storage-encryption.md`](rds-storage-encryption.md) 와 함께 본다.

---

## 1. 통제 항목

| 항목 | 값 |
|------|-----|
| 통제 ID | `ebs-encryption-default` |
| 탐지 규칙 | AWS Config 관리형 규칙 `EC2_EBS_ENCRYPTION_BY_DEFAULT` |
| 위반 상태 | 리전 계정 설정 "EBS 기본 암호화"가 꺼짐 → `NON_COMPLIANT` |
| 심각도 | 중간 (신규 볼륨이 평문으로 생성될 위험) |
| 조치 방식 | 자동 (EventBridge → Lambda), 비파괴 — **예방만** |
| 트리거 | **주기(Periodic)** |

### 무엇이 위반인가
이 규칙은 개별 볼륨이 아니라 **계정+리전 단위 설정** "EBS 기본 암호화(EBS encryption
by default)"를 평가한다. 이 설정이 꺼져 있으면 NON_COMPLIANT 다. 테스트는
`aws_ebs_encryption_by_default { enabled = false }` 로 이 상태를 명시 고정하고, 태그된
미암호화 볼륨 1개를 함께 만들어 "지금 평문 저장 데이터가 존재함"을 구체화한다.

---

## 2. 자동 조치 흐름 (예방)

```
계정 EBS 기본 암호화 OFF
  → Config 규칙 평가 = NON_COMPLIANT   (주기 규칙 — 즉시 확인은 강제 평가 필요)
  → EventBridge 규칙(compliance change 필터) 매칭
  → 조치 Lambda 호출
  → EnableEbsEncryptionByDefault 로 계정 기본 암호화 ON
  → Config 재평가 = COMPLIANT
```

### 조치 함수 동작
- **멱등적**: `get_ebs_encryption_by_default` 로 확인해, 이미 켜져 있으면
  `status="already_compliant"`.
- **비파괴적 · 예방만**: 계정 기본 암호화를 켠다. 이 설정은 **"신규" 볼륨과 스냅샷
  복사에만** 적용된다. **기존 볼륨은 전혀 건드리지 않는다**(암호화 상태 불변).
- **관측 가능**: 결과를 JSON 한 줄 구조화 로그로 남긴다. 예:
  ```json
  {"control":"ebs-encryption-default","ebs_encryption_by_default":true,"event_type":"remediation","status":"applied","timestamp":"..."}
  ```
- **상태값**: `applied` / `already_compliant` / `error`.

로그는 `/aws/lambda/<project_name>-ebs-encryption-default` 로그 그룹에 쌓인다.

> ⚠️ **주기(Periodic) 규칙이다.** S3(변경 트리거)와 달리 최초 NON_COMPLIANT 나 조치 후
> COMPLIANT 를 **즉시** 보려면 `start-config-rules-evaluation` 로 강제해야 한다. 강제하지
> 않으면 최대 24시간 뒤 자동 평가된다.

---

## 3. 왜 기존 볼륨은 자동 조치하지 않는가 (핵심 근거)

**EBS 는 기존 볼륨을 제자리(in-place)에서 암호화할 수 없다.** 기존 미암호화 볼륨을
암호화하려면 다음의 파괴적 절차가 필요하다.

1. 볼륨 스냅샷 생성 → 2. 스냅샷을 **암호화하여 복사**(copy-snapshot with KMS) →
3. 암호화 스냅샷에서 **새 볼륨 생성** → 4. 인스턴스에서 기존 볼륨 detach →
5. 새(암호화) 볼륨 attach.

이 과정은 **detach/attach 로 인한 다운타임**을 유발하고, 루트 볼륨이면 인스턴스 중지가
필요하다. 즉 S3(설정만 바꾸면 끝)와 달리 **가역적·비파괴로 자동화할 수 없다.** 그래서
이 통제의 자동 조치는 "앞으로 만들어질 볼륨을 안전하게"(예방)까지만 하고, **기존 볼륨의
실제 암호화는 사람의 계획·승인 아래 수동으로** 수행한다.

### 기존 미암호화 볼륨 수동 교정 절차 (파괴적 — 승인 후)
```bash
VOL=<기존 미암호화 볼륨 ID>
AZ=$(aws ec2 describe-volumes --volume-ids $VOL --query 'Volumes[0].AvailabilityZone' --output text)

# 1) 스냅샷
SNAP=$(aws ec2 create-snapshot --volume-id $VOL --query SnapshotId --output text)
aws ec2 wait snapshot-completed --snapshot-ids $SNAP

# 2) 암호화하여 복사
ENC_SNAP=$(aws ec2 copy-snapshot --source-region <REGION> --source-snapshot-id $SNAP \
  --encrypted --query SnapshotId --output text)
aws ec2 wait snapshot-completed --snapshot-ids $ENC_SNAP

# 3) 암호화 스냅샷에서 새 볼륨 생성
NEWVOL=$(aws ec2 create-volume --availability-zone $AZ --snapshot-id $ENC_SNAP \
  --volume-type gp3 --query VolumeId --output text)

# 4~5) (인스턴스 사용 중이면) 중지 → detach 기존 → attach 신규 → 시작
#   aws ec2 stop-instances / detach-volume / attach-volume / start-instances
```

---

## 4. 검증

```bash
# 1) 계정 기본 암호화가 켜졌는지 확인
aws ec2 get-ebs-encryption-by-default   # EbsEncryptionByDefault: true

# 2) 주기 규칙 즉시화 — 강제 재평가
aws configservice start-config-rules-evaluation \
  --config-rule-names <project_name>-ec2-ebs-encryption-by-default

# 3) 규칙이 COMPLIANT 로 바뀌었는지 확인
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name <project_name>-ec2-ebs-encryption-by-default \
  --compliance-types COMPLIANT
```

CloudWatch Logs 에서 조치 로그(`status=applied`)를 함께 확인한다.

---

## 5. 롤백 · 예외 처리

- **롤백(가역)**: 계정 기본 암호화를 다시 끄면 NON_COMPLIANT 로 돌아간다(재검증에도 사용).
  ```bash
  aws ec2 disable-ebs-encryption-by-default
  ```
- **조치 실패(`status=error`)**: 로그의 `error_type`/`error` 확인. 흔한 원인은 권한 부족.

---

## 6. Terraform 드리프트 주의

계정 기본 암호화(OFF)는 `aws_ebs_encryption_by_default { enabled = false }` 로 Terraform 이
관리한다. 조치 Lambda 가 이를 ON 으로 바꾸면 상태와 실제가 어긋난다.
- 조치 후 `terraform plan` 에 드리프트가 뜨는 것은 정상이다.
- `terraform apply` 하면 다시 OFF(취약)로 리셋된다 → 재검증에 활용.
- 이 Terraform 리소스를 destroy 로 제거하면 계정 기본 암호화가 자동 비활성화된다.

---

## 7. 참고
- 규칙 세부: https://docs.aws.amazon.com/config/latest/developerguide/ec2-ebs-encryption-by-default.html
- EBS 기본 암호화: https://docs.aws.amazon.com/ebs/latest/userguide/encryption-by-default.html
- 미암호화 리소스 암호화 전환: https://docs.aws.amazon.com/ebs/latest/userguide/ebs-encryption.html
