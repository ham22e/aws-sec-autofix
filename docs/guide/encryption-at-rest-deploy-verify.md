# 배포 & 검증 가이드 — 미암호화 리소스

`terraform apply` 로 배포한 뒤, **두 개의 자동 조치 루프**(S3 KMS · EBS 기본 암호화)를
탐지 → 자동 조치 → `COMPLIANT` 전환까지 각각 한 사이클 확인하는 절차다.
(조치 상세·수동 절차는 `docs/runbooks/` 의 각 런북 참고.)

> 리전: **ap-northeast-2 (서울)**. 콘솔 우상단 리전이 서울인지 먼저 확인한다.

리소스 이름은 `project_name`(기본 `autofix`) 접두사를 쓴다.

| 리소스 | 이름(기본값) |
|--------|--------------|
| 취약 S3 버킷 (SSE-S3) | `autofix-unencrypted-<임의suffix>` |
| S3 대상 KMS 키 별칭 | `alias/autofix-s3` |
| S3 Config 규칙 | `autofix-s3-default-encryption-kms` |
| S3 조치 Lambda | `autofix-s3-kms-encryption` |
| 취약 EBS 볼륨 | 태그 `Name=autofix-unencrypted` |
| EBS Config 규칙 | `autofix-ec2-ebs-encryption-by-default` |
| EBS 조치 Lambda | `autofix-ebs-encryption-default` |

---

## 0. 사전 준비

1. `terraform/terraform.tfvars` 에 배포 프로필 지정(예: `aws_profile = "your-aws-profile"`).
2. 배포 권한: `docs/deploy-iam-policy.json`(암호화 시나리오용 ec2/kms 권한 포함) 또는
   (격리 계정이면) `AdministratorAccess`.
3. 자격증명 확인:
   ```bash
   AWS_PROFILE=<프로필> aws sts get-caller-identity
   ```

> ⚠️ 이 시나리오는 **계정 EBS 기본 암호화 설정을 끄고(취약)** 켜는(조치) 동작을 한다.
> 계정+리전 단위 설정이므로 **격리 테스트 계정**에서만 진행한다.

---

## 1. 배포 (terraform apply)

```bash
cd terraform
terraform plan      # 생성될 리소스 검토
terraform apply     # yes 입력
```

`apply` 후 출력에서 실제 이름을 확인한다:
```bash
terraform output
# s3_kms_vulnerable_bucket    = "autofix-unencrypted-xxxx"
# s3_kms_config_rule_name     = "autofix-s3-default-encryption-kms"
# s3_kms_lambda_function_name = "autofix-s3-kms-encryption"
# ebs_vulnerable_volume_id    = "vol-xxxx"
# ebs_config_rule_name        = "autofix-ec2-ebs-encryption-by-default"
# ebs_lambda_function_name    = "autofix-ebs-encryption-default"
```

---

## 2. 배포 리소스 확인 (콘솔)

- **S3** → `autofix-unencrypted-...` → **속성 → 기본 암호화** 가 **SSE-S3(AES256)**
  인지(= 취약, KMS 아님). 태그에 `Purpose=intentionally-vulnerable`.
- **KMS** → 고객관리형 키 `alias/autofix-s3` 존재 확인.
- **EC2 → Elastic Block Store → 볼륨** → `autofix-unencrypted` 볼륨이
  **암호화 안 됨(Not encrypted)** 인지. 태그 `Purpose=intentionally-vulnerable`.
- **EC2 → 설정(Settings) → 데이터 보호 및 보안** → **EBS 암호화** 가 **꺼짐** 인지(= 취약).
- **AWS Config → 규칙** → 위 두 Config 규칙 존재 확인.
- **Lambda** → 두 조치 함수 → **구성 → 트리거** 에 EventBridge 연결 확인.

---

## 3. S3 루프 검증 (변경 트리거 — 자동으로 닫힘)

S3 규칙은 **구성 변경 트리거**라, 조치가 곧바로 재평가를 부른다.

```bash
B=$(terraform output -raw s3_kms_vulnerable_bucket)
R=$(terraform output -raw s3_kms_config_rule_name)

# (즉시 확인용) 규칙 강제 평가 → NON_COMPLIANT 확인
aws configservice start-config-rules-evaluation --config-rule-names $R
aws configservice get-compliance-details-by-config-rule --config-rule-name $R

# 잠시 후: 조치 Lambda 로그에서 status=applied 확인
#   CloudWatch → /aws/lambda/autofix-s3-kms-encryption

# 버킷 기본 암호화가 aws:kms 로 바뀌었는지
aws s3api get-bucket-encryption --bucket $B

# 규칙이 COMPLIANT 로 전환됐는지 (몇 분 내 자동)
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name $R --compliance-types COMPLIANT
```

여기까지 오면 **탐지(NON_COMPLIANT) → 자동 조치(KMS 적용) → COMPLIANT** 한 사이클 완료.

---

## 4. EBS 루프 검증 (주기 트리거 — 강제 평가 필요)

EBS 규칙은 **주기(Periodic) 규칙**이라, 최초/재평가를 즉시 보려면 강제해야 한다.

```bash
ER=$(terraform output -raw ebs_config_rule_name)

# 1) 강제 평가 → NON_COMPLIANT 확인 (계정 기본 암호화 꺼짐)
aws configservice start-config-rules-evaluation --config-rule-names $ER
aws configservice get-compliance-details-by-config-rule --config-rule-name $ER

# 2) 조치 Lambda 로그에서 status=applied 확인
#   CloudWatch → /aws/lambda/autofix-ebs-encryption-default

# 3) 계정 기본 암호화가 켜졌는지
aws ec2 get-ebs-encryption-by-default    # EbsEncryptionByDefault: true

# 4) 다시 강제 평가 → COMPLIANT 확인
aws configservice start-config-rules-evaluation --config-rule-names $ER
aws configservice get-compliance-details-by-config-rule \
  --config-rule-name $ER --compliance-types COMPLIANT
```

> 기존 미암호화 볼륨은 이 조치로 **바뀌지 않는다**(예방만). 기존 볼륨 실제 암호화는
> 런북 `ebs-encryption-default.md` 3번(수동·파괴적) 참고.

---

## 5. 멱등성 확인 (선택)

각 Lambda 를 직접 재-invoke 하면 이미 조치된 상태라 `already_compliant` 가 나온다.
```bash
aws lambda invoke --function-name autofix-ebs-encryption-default \
  --cli-binary-format raw-in-base64-out --payload '{}' /dev/stdout
```

---

## 6. 재검증 & 정리

- **다시 취약 상태로 리셋**(재검증): 조치 Lambda 가 바꾼 값 때문에 드리프트가 뜬다.
  ```bash
  terraform apply   # S3=SSE-S3, EBS 계정설정=off 로 되돌림 → 재-NON_COMPLIANT 준비
  ```
  (조치 후 `terraform plan` 에 암호화 드리프트가 뜨는 것은 정상. EventBridge 는 상태가
  아니라 *전환*에만 발동하므로, 규칙을 켠 채로 COMPLIANT→NON_COMPLIANT 전환을 만든다 —
  S3 퍼블릭 노출 시나리오와 동일.)

- **완전 정리**:
  ```bash
  terraform destroy
  ```
  ⚠️ **KMS 키는 즉시 삭제되지 않고 7일 삭제 대기**로 들어간다(별칭은 즉시 해제). EBS 계정
  기본 암호화 설정 리소스는 destroy 시 자동 비활성화된다.

---

## 7. 트러블슈팅

| 증상 | 확인 |
|------|------|
| EBS 규칙이 계속 평가 안 됨 | **주기 규칙**이라 자동 평가는 최대 24h. `start-config-rules-evaluation` 강제 |
| S3 규칙이 다른 버킷까지 안 잡음 | 정상. 규칙 scope 를 테스트 버킷 하나로 좁혀 뒀다(blast radius 한정) |
| Lambda 로그가 안 생김 | EventBridge 대상/`lambda_permission` 확인. 규칙이 아직 NON_COMPLIANT 가 안 됐을 수 있음 |
| `status=error` (S3) | 역할에 대상 버킷 ARN·키 ARN 권한, 키 정책 확인 |
| `status=error` (EBS) | 역할에 `ec2:EnableEbsEncryptionByDefault` 권한 확인 |
| 규칙은 켰는데 NON_COMPLIANT 인 채 조치가 안 돎 | 규칙을 껐다 켜서 **전환 이벤트를 놓친** 경우. Lambda 직접 invoke 로 확인 |
| `apply` 가 recorder 중복으로 실패 | 계정에 이미 Config Recorder 존재 → `manage_config_baseline=false` |

---

관련 문서: 조치 상세·CLI 절차는 각 런북
[`s3-kms-encryption.md`](../runbooks/s3-kms-encryption.md),
[`ebs-encryption-default.md`](../runbooks/ebs-encryption-default.md),
[`rds-storage-encryption.md`](../runbooks/rds-storage-encryption.md).
