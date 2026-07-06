# 배포 & 검증 가이드: 가시화 대시보드

`terraform apply` 로 배포한 뒤, 조치 이력과 Config 준수율이 **하나의 CloudWatch
대시보드에서 한눈에** 보이는지 확인하는 절차다. 대시보드는 탐지→조치 시나리오가
아니라, 앞선 시나리오들이 남긴 조치 로그(metric filter)와 Config 준수 상태
(발행 Lambda)를 시각화하는 공통 운영 계층이다.

> 리전: **ap-northeast-2 (서울)**. 콘솔 우상단 리전이 서울인지 먼저 확인한다.
> 다른 리전을 보고 있으면 대시보드·메트릭이 안 보인다.

리소스 이름은 `project_name`(기본 `autofix`) 접두사를 쓴다.

| 리소스 | 이름(기본값) |
|--------|--------------|
| CloudWatch 대시보드 | `autofix-overview` |
| 준수율 발행 Lambda | `autofix-compliance-metrics` |
| 스케줄 규칙 | `autofix-compliance-metrics-schedule` |
| 조치 메트릭 네임스페이스 | `AutoFix/Remediation` (metric `RemediationEvent`) |
| 준수 메트릭 네임스페이스 | `AutoFix/Compliance` (`ComplianceRate`, `RuleCompliance` 등) |

---

## 0. 사전 준비

1. `terraform/terraform.tfvars` 에 배포 프로필 지정(예: `aws_profile = "내프로필"`).
2. 그 프로필/자격증명에 배포 권한 부여: `docs/deploy-iam-policy.json` 또는
   (격리 계정이면) `AdministratorAccess`.
3. 자격증명 확인:
   ```bash
   AWS_PROFILE=<프로필> aws sts get-caller-identity
   ```

> 전제: 탐지·조치 시나리오와 로그 레이크가 이미 배포되어 조치 Lambda 로그 그룹 5개
> (`/aws/lambda/autofix-*`)와 Config 규칙 4개가 존재해야 metric filter·
> 준수율 판정이 붙는다. 루트 `main.tf` 의 `depends_on` 이 이 순서를 보장한다.

---

## 1. 배포 (terraform apply)

```bash
cd terraform
terraform plan      # 생성될 리소스 검토 (기존 리소스 변경 없이 신규만 추가)
terraform apply     # yes 입력
```

`apply` 완료 후 출력에서 실제 이름·링크를 확인한다:
```bash
terraform output | grep -E "dashboard|compliance_metrics"
# dashboard_name             = "autofix-overview"
# dashboard_url              = "https://ap-northeast-2.console.aws.amazon.com/cloudwatch/home?region=ap-northeast-2#dashboards/dashboard/autofix-overview"
# compliance_metrics_lambda  = "autofix-compliance-metrics"
```

---

## 2. 배포 리소스 확인 (콘솔)

### 2-1. 대시보드
- `dashboard_url` 링크를 열거나 **CloudWatch → 대시보드** →
  `autofix-overview`. 위젯 6개(준수율 게이지, 준수/미준수 수 추이, 규칙별
  준수 상태, control·status별 조치 이벤트, 조치 타임라인, control x status 집계)가
  보이는지 확인.

### 2-2. metric filter (조치 로그 → 메트릭)
- **CloudWatch → 로그 → 로그 그룹** → 임의의 조치 로그 그룹(예:
  `/aws/lambda/autofix-s3-remediation`) → **메트릭 필터** 탭에
  `autofix-remediation-event` 가 붙어 있는지 확인. 5개 로그 그룹에 각각
  하나씩 있다.

### 2-3. 준수율 발행 Lambda + 스케줄
- **Lambda** → `autofix-compliance-metrics` → 트리거에 EventBridge
  스케줄(`rate(5 minutes)`)이 연결돼 있는지 확인.

---

## 3. 데이터 채우기 (위젯이 채워지려면)

대시보드 메트릭은 **배포 후 발생한 데이터**로만 채워진다(백필 없음). 두 종류다.

- **준수율(AutoFix/Compliance)**: 스케줄 Lambda 가 5분마다 자동 발행한다. 즉시 보고
  싶으면 한 번 수동 호출한다:
  ```bash
  aws lambda invoke --function-name autofix-compliance-metrics /dev/stdout
  ```
  이후 준수율 게이지·규칙별 준수 상태 위젯이 채워진다(메트릭 반영에 1~2분).

- **조치 이벤트(AutoFix/Remediation)**: 실제 조치가 한 번 일어나야 metric filter 가
  집계한다. 예를 들어 S3 취약 버킷을 다시 취약화하면 조치 Lambda 가 실행되고,
  그 로그가 metric filter 를 통해 메트릭이 된다.
  ```bash
  # S3 시나리오 재검증으로 조치 1건 유발 (자세한 절차는 s3-public-access 가이드 참고)
  terraform apply    # 취약 버킷 BPA 를 다시 off → 조치 Lambda 실행
  ```
  조치 후 1~2분 뒤 "조치 이벤트" 위젯과 타임라인에 반영된다.

---

## 4. 대시보드 판독 (핵심 = DoD)

`dashboard_url` 을 열고 확인한다.

- **준수율(%) 게이지 / 규칙별 준수 상태**: 조치 전에는 위반 규칙이 있어 준수율이
  100% 미만이고 해당 규칙이 0(미준수)으로 보인다. 조치가 되고 Config 재평가가
  끝나면 준수율이 오르고 규칙이 1(준수)로 바뀐다. 게이지·"준수/미준수 수"는
  **선택한 시간 범위** 기준으로 집계된다(게이지 stat=Maximum). 배포 직후의 옛
  스냅샷이 창에 남아 있으면 잠시 값이 어긋나 보일 수 있으니, 값이 이상하면 시간
  범위를 좁혀(예: 15분) 최신 스냅샷만 보면 된다.
- **control·status별 조치 이벤트**: 방금 유발한 조치가 control(예:
  `s3-public-access`)·status(예: `applied`)별로 잡힌다. 누적 조회는 아래 타임라인·
  집계 위젯이 정확하다.
- **조치 타임라인**: "언제 무엇이 어떻게 조치됐는지"가 시간 역순 표로 보인다.
  이 위젯이 대시보드 DoD("탐지→조치 이력이 시각적으로 확인 가능")의 핵심이다.

여기까지 오면 조치 이력과 준수율이 **한 화면에서 시각적으로 확인**되는
대시보드 DoD 가 재현된 것이다.

---

## 5. 정리

```bash
terraform destroy
```
대시보드·metric filter·준수율 Lambda·스케줄 규칙 모두 삭제된다. 발행된 커스텀
메트릭(AutoFix/Remediation·AutoFix/Compliance)은 CloudWatch 에 최대 15개월 보존 후
자동 만료된다(별도 삭제 API 없음, 과금 없음).

---

## 6. 트러블슈팅

| 증상 | 확인 |
|------|------|
| 조치 이벤트 위젯이 비어 있음 | metric filter 는 **배포 후 신규 조치**만 집계(백필 없음). 3번으로 조치를 실제 유발했는지, 로그 그룹에 메트릭 필터가 붙었는지(2-2) 확인 |
| 준수율 게이지가 비어 있음/0 | (1) 스케줄(최대 5분) 대기 또는 3번으로 수동 invoke. (2) 규칙이 아직 `INSUFFICIENT_DATA`(최초 평가 전)면 준수율 분모에서 제외되어 datapoint 가 없다. Config 평가 후 재확인 |
| 규칙별 준수 상태가 일부만 보임 | `INSUFFICIENT_DATA`·`NOT_APPLICABLE` 규칙은 판정 불가라 선을 그리지 않는다(의도된 동작) |
| 타임라인이 비어 있음 | 조치 로그가 아직 없거나, 위젯 시간 범위가 조치 시각을 벗어남. 우상단 시간 범위를 넓혀 재확인 |
| 리소스가 콘솔에 안 보임 | 우상단 **리전이 서울(ap-northeast-2)** 인지 |

---

## 참고: 설계 메모

- **시각화 방식**: DynamoDB·QuickSight 대신 **CloudWatch 대시보드**. 100% IaC,
  거의 무비용, `terraform destroy` 로 완전 정리. 조치 이력 저장소는 이미 로그 레이크
  (로그 그룹 + 로그 레이크)에 있어 별도 저장소를 만들지 않는다(중복 회피).
- **데이터 소스**: 조치 이력은 로그 그룹을 직접(metric filter·Logs Insights) 읽는다.
  CloudWatch 대시보드는 Athena 를 위젯으로 못 붙이므로, 로그 레이크(감사·장기 분석,
  Athena)와 대시보드(운영 현황 실시간)로 역할이 갈린다.
- **준수율**: 조치 로그엔 없는 값이라, 준수율 발행 Lambda 가 Config 준수 상태를
  읽어 `AutoFix/Compliance` 커스텀 메트릭으로 낸다(읽기 전용·비파괴). 트리거는 스케줄
  `rate(5 minutes)` 단일. Config 컴플라이언스 변경 이벤트 트리거 병행은 향후 확장.
- 조치 Lambda 코드는 **변경하지 않았다**. 이미 남기던 정규화 JSON 로그가 그대로
  metric filter·타임라인의 입력이 된다.
