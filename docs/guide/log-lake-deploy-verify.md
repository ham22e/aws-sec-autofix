# 배포 & 검증 가이드: 로그 레이크

`terraform apply` 로 배포한 뒤, 세 소스(CloudTrail·VPC Flow Logs·조치 Lambda
로그)가 **하나의 S3 버킷에 모이고 Athena 로 조치 이력을 조회**할 수 있는지
확인하는 절차다. 로그 레이크는 탐지→조치 시나리오가 아니라, 앞선 시나리오들이
남긴 로그를 수집·분석하는 공통 인프라다.

> 리전: **ap-northeast-2 (서울)**. 콘솔 우상단 리전이 서울인지 먼저 확인한다.
> 다른 리전을 보고 있으면 리소스가 안 보인다.

리소스 이름은 `project_name`(기본 `autofix`) 접두사를 쓴다.

| 리소스 | 이름(기본값) |
|--------|--------------|
| 로그 레이크 S3 버킷 | `autofix-log-lake-<임의suffix>` |
| CloudTrail 트레일 | `autofix-trail` |
| Firehose 스트림 | `autofix-remediation-logs` |
| 변환 Lambda | `autofix-log-lake-processor` |
| Glue 데이터베이스 | `autofix_log_lake` (하이픈→언더스코어) |
| Athena 작업 그룹 | `autofix-log-lake` |

---

## 0. 사전 준비

1. `terraform/terraform.tfvars` 에 배포 프로필 지정(예: `aws_profile = "내프로필"`).
2. 그 프로필/자격증명에 배포 권한 부여: `docs/deploy-iam-policy.json` 또는
   (격리 계정이면) `AdministratorAccess`.
3. 자격증명 확인:
   ```bash
   AWS_PROFILE=<프로필> aws sts get-caller-identity
   ```
4. 토글 확인(선택):
   - 계정/조직에 **이미 CloudTrail 트레일이 있으면** `enable_cloudtrail = false`
     로 두어 중복 생성을 피한다.
   - **기본 VPC 가 없는 계정**이면 `enable_vpc_flow_logs = false` 로 둔다
     (기본 VPC 대상 Flow Logs 를 만들 수 없다).

> 전제: 탐지·조치 시나리오(S3·IAM·암호화)가 이미 배포되어 조치 Lambda 로그 그룹 5개
> (`/aws/lambda/autofix-*`)가 존재해야 구독 필터가 연결된다.
> 루트 `main.tf` 의 `depends_on` 이 이 순서를 보장한다.

---

## 1. 배포 (terraform apply)

```bash
cd terraform
terraform plan      # 생성될 리소스 검토 (기존 리소스 변경 없이 신규만 추가)
terraform apply     # yes 입력
```

`apply` 완료 후 출력에서 실제 이름을 확인한다:
```bash
terraform output | grep log_lake
# log_lake_bucket            = "autofix-log-lake-xxxxxxxx"
# log_lake_glue_database     = "autofix_log_lake"
# log_lake_athena_workgroup  = "autofix-log-lake"
# log_lake_cloudtrail_name   = "autofix-trail"
# log_lake_firehose_stream   = "autofix-remediation-logs"
```

---

## 2. 배포 리소스 확인 (콘솔)

### 2-1. 로그 레이크 S3 버킷
- **S3** → `autofix-log-lake-...` 클릭.
- **속성** → 기본 암호화 = **SSE-S3(AES256)**, **권한** → 퍼블릭 액세스 차단
  4종 모두 켜짐.

### 2-2. CloudTrail
- **CloudTrail → 추적(Trails)** → `autofix-trail` → **로깅 켜짐(Logging on)**,
  대상 버킷이 로그 레이크 버킷인지 확인.

### 2-3. Firehose + 구독 필터 (조치 로그 경로)
- **Amazon Data Firehose** → 스트림 `autofix-remediation-logs` →
  대상 = 로그 레이크 버킷 `remediation/` 프리픽스, 변환(Transform) = Lambda
  `autofix-log-lake-processor`.
- **CloudWatch → 로그 그룹** → 임의의 조치 로그 그룹(예:
  `/aws/lambda/autofix-s3-remediation`) → **구독 필터(Subscription filters)**
  탭에 `autofix-to-log-lake` 가 Firehose 로 연결돼 있는지 확인.

### 2-4. Glue / Athena
- **AWS Glue → 데이터베이스** → `autofix_log_lake` → 테이블 3개
  (`remediation_logs`, `cloudtrail_logs`, `vpc_flow_logs`).
- **Athena → 작업 그룹** → `autofix-log-lake` 존재 확인. 쿼리 편집기
  상단에서 이 작업 그룹을 선택한다.

---

## 3. 로그 적재 확인 (세 소스가 한 버킷에)

로그 레이크 버킷을 열어 프리픽스 3종이 채워지는지 본다. CloudTrail·Flow Logs 는
전달 지연(수 분~15분)이 있을 수 있다.

```bash
B=$(terraform output -raw log_lake_bucket)
aws s3 ls s3://$B/ --recursive | awk '{print $4}' | cut -d/ -f1 | sort -u
# AWSLogs        ← CloudTrail (AWSLogs/<account>/CloudTrail/...)
# vpc-flow       ← VPC Flow Logs
# remediation    ← 조치 Lambda 로그 (Firehose 경유)
```

조치 로그(`remediation/`)를 확실히 만들려면 조치를 한 번 유발한다. 예를 들어
S3 취약 버킷을 다시 취약화하면 조치 Lambda 가 실행되고, 그 로그가
구독 필터 → Firehose(버퍼 최대 60초) → S3 로 흐른다.

```bash
# S3 시나리오 재검증으로 조치 1건 유발 (자세한 절차는 s3-public-access 가이드 6번)
terraform apply    # 취약 버킷 BPA 를 다시 off → 조치 Lambda 실행
# 1~2분 뒤 remediation 프리픽스에 객체가 생기는지 확인
aws s3 ls s3://$B/remediation/ --recursive
```

---

## 4. Athena 로 조치 이력 조회 (핵심 = DoD)

**Athena → 쿼리 편집기**에서 작업 그룹 `autofix-log-lake`,
데이터베이스 `autofix_log_lake` 를 선택한다. 배포 시 저장된
**명명된 쿼리(Saved queries)** 4개를 그대로 실행할 수 있다.

### 4-1. 최근 조치 이력 (control·status 집계)
```sql
SELECT control, status, count(*) AS events, max(timestamp) AS last_seen
FROM remediation_logs
GROUP BY control, status
ORDER BY control, status;
```
기대: `s3-public-access / applied`, `... / already_compliant` 등 조치 건수가
control 별로 집계된다. 방금 유발한 조치가 한 줄로 잡히면 DoD 충족.

### 4-2. 실패한 조치만 추출
```sql
SELECT timestamp, control, bucket, error_type, error
FROM remediation_logs
WHERE status = 'error'
ORDER BY timestamp DESC;
```

### 4-3. 조치 Lambda 가 호출한 API 추적 (CloudTrail 상관)
```sql
SELECT eventtime, eventsource, eventname, useridentity.arn AS actor
FROM cloudtrail_logs
WHERE useridentity.arn LIKE '%-remediation-role%'
   OR useridentity.arn LIKE '%-encryption%'
ORDER BY eventtime DESC
LIMIT 100;
```
기대: 조치 Lambda 역할이 실제로 `PutBucketPublicAccessBlock` 등을 호출한
기록이 조치 로그와 시간상 대응한다(조치가 진짜 일어났음을 감사 로그로 교차 검증).

### 4-4. 누가 S3 퍼블릭 설정을 바꿨나
```sql
SELECT eventtime, eventname, useridentity.arn AS actor, sourceipaddress
FROM cloudtrail_logs
WHERE eventsource = 's3.amazonaws.com'
  AND eventname IN ('PutBucketPublicAccessBlock', 'DeletePublicAccessBlock', 'PutBucketPolicy')
ORDER BY eventtime DESC
LIMIT 100;
```

여기까지 오면 **세 소스가 한 버킷에 모이고, 조치 이력을 SQL 로 조회**하는
로그 레이크 DoD 가 재현된 것이다.

---

## 5. 정리

```bash
terraform destroy
```
로그 레이크 버킷은 `force_destroy = true` 라 쌓인 로그 객체까지 함께 삭제된다.
Athena 작업 그룹도 `force_destroy` 로 쿼리 이력과 함께 정리된다.

> ⚠️ 이 스택이 만든 CloudTrail 은 `destroy` 로 삭제된다. `enable_cloudtrail=false`
> 로 두어 **기존 계정/조직 트레일을 재사용**한 경우엔 그 트레일은 건드리지 않는다.

---

## 6. 트러블슈팅

| 증상 | 확인 |
|------|------|
| `remediation/` 에 객체가 안 생김 | (1) 조치를 실제로 유발했는지(3번). (2) 로그 그룹의 **구독 필터**가 붙어 있는지(2-3). (3) Firehose 버퍼는 최대 60초 지연. Firehose 콘솔의 **Monitoring** 과 오류 프리픽스 `remediation-errors/` 확인 |
| Athena 쿼리는 되는데 `remediation_logs` 가 0행 | 아직 조치 로그가 안 쌓였거나 버퍼 지연. `s3 ls remediation/` 로 객체부터 확인 |
| `cloudtrail_logs` / `vpc_flow_logs` 0행 | CloudTrail·Flow Logs 는 최초 전달까지 **수 분~15분** 걸린다. 잠시 후 재조회 |
| 쿼리 결과가 깨져 보임(파싱 오류) | 테이블 위치(프리픽스)와 실제 적재 경로가 맞는지. CloudTrail 은 `AWSLogs/<account>/CloudTrail/`, Flow Logs 는 `vpc-flow/` 하위에 쌓인다 |
| `apply` 가 CloudTrail 중복/버킷 정책으로 실패 | 계정에 이미 트레일이 있으면 `enable_cloudtrail=false`. 버킷 정책 반영 전 트레일 생성 순서는 `depends_on` 으로 보장됨 |
| Flow Logs 생성 실패(기본 VPC 없음) | `enable_vpc_flow_logs=false` 로 두고 재배포 |
| 리소스가 콘솔에 안 보임 | 우상단 **리전이 서울(ap-northeast-2)** 인지 |

---

## 참고: 설계 메모

- **저장·분석**: Security Lake 대신 **S3 + Athena(Glue)**. 테스트 비용·`destroy`
  용이성 우선. Security Lake(OCSF) 통합은 향후 확장 항목.
- **조치 로그 수집**: CloudWatch Logs → 구독 필터 → **Firehose(봉투 제거 변환
  Lambda)** → S3. CloudWatch Logs 가 Firehose 로 보내는 데이터는 gzip +
  `logEvents` 봉투라, 변환 Lambda 가 봉투를 벗겨 **원본 조치 JSON 한 줄**만
  저장한다. 그래서 `remediation_logs` 테이블이 추가 파싱 없이 조회된다.
- **Glue 테이블**: 크롤러 없이 프리픽스 전체를 스캔한다(테스트 데이터 규모에
  충분). 데이터가 커지면 파티션 프로젝션 추가가 향후 최적화 항목.
- 조치 Lambda 코드는 **변경하지 않았다**. 이미 남기던 정규화 JSON 로그가
  그대로 로그 레이크의 입력이 된다.
