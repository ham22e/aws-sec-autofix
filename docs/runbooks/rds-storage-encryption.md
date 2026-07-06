# 런북 — RDS 저장 데이터 암호화 (수동 · 교정 전용)

이 런북은 **조치 함수가 없는 수동 런북**이다. 미암호화 리소스 시나리오에서 RDS 는
"자동 조치를 두지 않는(못 두는) 경우"의 대표 사례로, 왜 그러한지와 사람이 계획·승인 아래
수행하는 교정 절차를 담는다.

> 미암호화 리소스 3종의 조치 스펙트럼: **S3(완전 자동) → EBS(예방만 자동) → RDS(수동만)**.
> 함께 보기: [`s3-kms-encryption.md`](s3-kms-encryption.md),
> [`ebs-encryption-default.md`](ebs-encryption-default.md).

---

## 1. 통제 항목

| 항목 | 값 |
|------|-----|
| 통제 ID | `rds-storage-encryption` (수동) |
| 탐지 규칙 | AWS Config 관리형 규칙 `RDS_STORAGE_ENCRYPTED` |
| 위반 상태 | RDS 인스턴스의 스토리지 암호화 미설정 → `NON_COMPLIANT` |
| 심각도 | 높음 (관계형 DB 저장 데이터 평문) |
| 조치 방식 | **수동만** (자동 조치 없음) |

> 이 테스트에서는 **RDS 를 라이브로 배포하지 않는다.** RDS 인스턴스는 생성·삭제에 각각
> 10~20분이 걸리고 비용이 발생하며, 무엇보다 아래 이유로 자동 조치 루프를 깔끔히
> 재현할 수 없어 **문서(런북)로만** 다룬다. 탐지 규칙 자체는 배포된 config-baseline
> 위에 추가로 켤 수 있다(선택).

---

## 2. 왜 자동 조치를 두지 않는가 (핵심 근거)

1. **제자리 암호화 불가**: 이미 만들어진 RDS 인스턴스의 스토리지 암호화 여부는
   **변경할 수 없다.** 암호화하려면 스냅샷 → 암호화 복사 → **새 인스턴스로 복원**해야 한다.
2. **계정 토글도 없다**: EBS 처럼 "기본 암호화 ON" 같은 계정 단위 예방 스위치가 없다.
   그래서 EBS 처럼 "예방만 자동"으로 우회할 여지도 없다.
3. **항상 파괴적**: 복원된 인스턴스는 **새 엔드포인트**를 가지므로 애플리케이션 접속 정보
   교체와 **다운타임(또는 컷오버)**이 불가피하다. 자동으로 안전하게 되돌릴 수 있는 조치가
   아니다.

→ 따라서 RDS 암호화 교정은 **사람의 계획·승인 아래 변경 창(maintenance window)** 에서
수행한다. 자동 조치 코드를 두는 것이 오히려 위험하다.

---

## 3. 수동 교정 절차 (승인 후, 변경 창에서)

```bash
DB=<대상 DB 인스턴스 식별자>
KMS=<사용할 KMS 키 ARN>

# 1) 원본 스냅샷
aws rds create-db-snapshot \
  --db-instance-identifier $DB \
  --db-snapshot-identifier ${DB}-preenc
aws rds wait db-snapshot-available --db-snapshot-identifier ${DB}-preenc

# 2) 스냅샷을 암호화하여 복사
aws rds copy-db-snapshot \
  --source-db-snapshot-identifier ${DB}-preenc \
  --target-db-snapshot-identifier ${DB}-enc \
  --kms-key-id $KMS
aws rds wait db-snapshot-available --db-snapshot-identifier ${DB}-enc

# 3) 암호화 스냅샷에서 새 인스턴스로 복원 (새 엔드포인트 생성)
aws rds restore-db-instance-from-db-snapshot \
  --db-instance-identifier ${DB}-encrypted \
  --db-snapshot-identifier ${DB}-enc

# 4) 컷오버: 앱 접속 정보를 새 엔드포인트로 교체 → 검증 → 구 인스턴스 정리
```

> ⚠️ 파라미터 그룹·옵션 그룹·서브넷 그룹·보안 그룹·태그·백업 설정 등을 신규 인스턴스에
> 동일하게 맞춘 뒤 컷오버한다. 리드 레플리카·멀티AZ 구성이면 추가 계획이 필요하다.

---

## 4. (선택) 탐지 규칙만 켜기

라이브 인스턴스 없이 규칙만 추가하려면 config-baseline 위에 다음 규칙을 켠다.
```hcl
resource "aws_config_config_rule" "rds_encrypted" {
  name = "${var.project_name}-rds-storage-encrypted"
  source {
    owner             = "AWS"
    source_identifier = "RDS_STORAGE_ENCRYPTED"
  }
}
```
인스턴스가 없으면 평가 대상이 없어 규칙은 비어 있는 상태가 된다(정상).

---

## 5. 예방 관점 (신규 인스턴스는 처음부터 암호화)

교정보다 예방이 싸다. 신규 RDS 는 생성 시 `--storage-encrypted --kms-key-id <KMS>` 로
반드시 암호화한다. Terraform 이면 `aws_db_instance` 에 `storage_encrypted = true` +
`kms_key_id` 를 강제하고, SCP/Config 로 미암호화 생성 자체를 막는 것이 가장 견고하다.

---

## 6. 참고
- 규칙 세부: https://docs.aws.amazon.com/config/latest/developerguide/rds-storage-encrypted.html
- RDS 암호화: https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html
- 기존 DB 암호화(스냅샷→복원): https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html#Overview.Encryption.Enabling
