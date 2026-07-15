locals {
  # 조치 Lambda 소스는 리포 루트의 lambda/<control>/ 에 있다.
  lambda_source_dir = "${path.root}/../lambda/s3-public-access"

  # IAM 과도 권한 시나리오는 탐지·알림 / 승인 조치 두 개의 Lambda 를 쓴다.
  iam_detect_lambda_dir  = "${path.root}/../lambda/iam-excessive-privilege/detect-notify"
  iam_approve_lambda_dir = "${path.root}/../lambda/iam-excessive-privilege/approve-remediate"

  # 미암호화 리소스 시나리오는 S3 KMS / EBS 기본암호화 두 개의 조치 Lambda 를 쓴다.
  s3_kms_lambda_dir  = "${path.root}/../lambda/s3-kms-encryption"
  ebs_enc_lambda_dir = "${path.root}/../lambda/ebs-encryption-default"

  # 로그 레이크는 조치 로그를 중앙 수집하는 Firehose 변환 Lambda 를 쓴다.
  log_lake_processor_dir = "${path.root}/../lambda/log-lake-processor"

  # 가시화 대시보드는 Config 준수 상태를 메트릭으로 발행하는 Lambda 를 쓴다.
  compliance_metrics_dir = "${path.root}/../lambda/compliance-metrics"

  # Config 규칙 이름. 루트가 소유한다(시나리오 모듈이 아니라).
  # 이렇게 해야 dashboard 의 준수율 Lambda 가 시나리오 모듈 output 에 의존하지 않고,
  # 아래 생성 순서를 지킬 수 있다.
  config_rules = {
    s3_public = "${var.project_name}-s3-bucket-public-read-prohibited"
    iam       = "${var.project_name}-iam-policy-no-admin-access"
    s3_kms    = "${var.project_name}-s3-default-encryption-kms"
    ebs       = "${var.project_name}-ec2-ebs-encryption-by-default"
  }
  config_rule_names = values(local.config_rules)

  # 조치 Lambda 로그 그룹. 루트가 소유한다(시나리오 모듈이 아니라).
  # 변환 Lambda 자신의 로그 그룹은 순환(로그→Firehose→변환→로그)을 피하려 제외한다.
  remediation_log_groups = {
    s3_public   = "/aws/lambda/${var.project_name}-s3-remediation"
    iam_detect  = "/aws/lambda/${var.project_name}-iam-detect-notify"
    iam_approve = "/aws/lambda/${var.project_name}-iam-approve-remediate"
    s3_kms      = "/aws/lambda/${var.project_name}-s3-kms-encryption"
    ebs         = "/aws/lambda/${var.project_name}-ebs-encryption-default"
  }
  remediation_log_group_names = values(local.remediation_log_groups)
}

# =====================================================================
# 조치 Lambda 로그 그룹 (루트 소유)
#
# ⚠️ 왜 모듈이 아니라 루트인가 — 생성 순서 때문이다.
#
# CloudWatch metric filter 와 구독 필터는 "생성된 이후"에 들어온 로그만 집계한다.
# 소급 적용이 없다. 그런데 조치 Lambda 는 Config 규칙이 생기는 즉시 발동한다.
#
# 로그 그룹이 시나리오 모듈 안에 있으면, 필터를 거는 dashboard·log-lake 모듈이
# 시나리오 모듈보다 뒤에 올 수밖에 없다(필터는 로그 그룹이 있어야 걸린다).
# 그 사이에 첫 조치가 일어나면 메트릭과 로그 레이크가 그 이벤트를 통째로 놓친다.
# (실제 배포에서 조치 4건이 전부 로그 레이크에서 누락된 적이 있다.)
#
# 로그 그룹을 루트로 올려 이 순서를 강제한다:
#   로그 그룹 → 필터(metric·subscription) → Config 규칙 → 첫 조치 → 집계됨
# =====================================================================
resource "aws_cloudwatch_log_group" "remediation" {
  for_each = local.remediation_log_groups

  name              = each.value
  retention_in_days = 14
}

# 계정 싱글턴 Config 인프라. Recorder 가 계정+리전당 1개 제약이 있어
# 기존 Config 가 있으면 manage_config_baseline=false 로 끈다.
module "config_baseline" {
  count  = var.manage_config_baseline ? 1 : 0
  source = "./modules/config-baseline"

  name_prefix = var.project_name
}

# =====================================================================
# 관측 계층 (로그 레이크 · 대시보드)
#
# 시나리오 모듈보다 "먼저" 만든다. 필터가 준비된 뒤에 Config 규칙이 생겨야
# 첫 조치 로그부터 집계에 잡힌다(위 aws_cloudwatch_log_group 주석 참고).
# =====================================================================

# 로그 레이크 (로깅 통합), 횡단 운영/분석 계층.
# CloudTrail·VPC Flow Logs·조치 Lambda 로그를 하나의 S3 버킷에 모아 Athena 로 조회한다.
module "log_lake" {
  source = "./modules/log-lake"

  name_prefix                 = var.project_name
  processor_lambda_source_dir = local.log_lake_processor_dir
  remediation_log_group_names = local.remediation_log_group_names
  enable_cloudtrail           = var.enable_cloudtrail
  enable_vpc_flow_logs        = var.enable_vpc_flow_logs

  # 구독 필터는 로그 그룹이 먼저 있어야 걸린다.
  depends_on = [aws_cloudwatch_log_group.remediation]
}

# 가시화 (대시보드 / 타임라인), 횡단 운영 계층.
# 조치 로그(metric filter)와 Config 준수 상태(발행 Lambda)를 CloudWatch 대시보드로 보여준다.
module "dashboard" {
  source = "./modules/dashboard"

  name_prefix                  = var.project_name
  remediation_log_group_names  = local.remediation_log_group_names
  config_rule_names            = local.config_rule_names
  compliance_lambda_source_dir = local.compliance_metrics_dir

  # metric filter 는 로그 그룹이 먼저 있어야 걸린다.
  # (Config 규칙 이름은 local.config_rules 에서 오므로 시나리오 모듈에 의존하지 않는다.)
  depends_on = [aws_cloudwatch_log_group.remediation]
}

# =====================================================================
# 탐지 → 조치 시나리오
#
# 관측 계층(log_lake · dashboard)이 완성된 뒤에 만든다. 각 모듈의 Config 규칙이
# 생성되는 순간 첫 평가와 조치가 일어나므로, 필터가 그보다 먼저 있어야 한다.
# =====================================================================

# 시나리오: S3 퍼블릭 노출 (탐지 → 자동 조치).
module "s3_public_access" {
  source = "./modules/s3-public-access"

  name_prefix       = var.project_name
  lambda_source_dir = local.lambda_source_dir
  config_rule_name  = local.config_rules.s3_public
  log_group_name    = aws_cloudwatch_log_group.remediation["s3_public"].name
  log_group_arn     = aws_cloudwatch_log_group.remediation["s3_public"].arn

  depends_on = [module.config_baseline, module.log_lake, module.dashboard]
}

# 시나리오: IAM 과도 권한 (탐지 → 알림 → 승인 기반 조치).
# S3 와 달리 자동 조치하지 않는다(권한 자동 회수 = 서비스 중단 위험).
module "iam_excessive_privilege" {
  source = "./modules/iam-excessive-privilege"

  name_prefix               = var.project_name
  detect_lambda_source_dir  = local.iam_detect_lambda_dir
  approve_lambda_source_dir = local.iam_approve_lambda_dir
  alert_email               = var.alert_email
  config_rule_name          = local.config_rules.iam

  detect_log_group_name  = aws_cloudwatch_log_group.remediation["iam_detect"].name
  detect_log_group_arn   = aws_cloudwatch_log_group.remediation["iam_detect"].arn
  approve_log_group_name = aws_cloudwatch_log_group.remediation["iam_approve"].name
  approve_log_group_arn  = aws_cloudwatch_log_group.remediation["iam_approve"].arn

  depends_on = [module.config_baseline, module.log_lake, module.dashboard]
}

# 시나리오: S3 저장 데이터 암호화 (KMS) — 탐지 → 자동 조치.
# 제자리 암호화가 가능한 경우(put-bucket-encryption 으로 SSE-KMS 적용).
module "s3_kms_encryption" {
  source = "./modules/s3-kms-encryption"

  name_prefix       = var.project_name
  lambda_source_dir = local.s3_kms_lambda_dir
  config_rule_name  = local.config_rules.s3_kms
  log_group_name    = aws_cloudwatch_log_group.remediation["s3_kms"].name
  log_group_arn     = aws_cloudwatch_log_group.remediation["s3_kms"].arn

  depends_on = [module.config_baseline, module.log_lake, module.dashboard]
}

# 시나리오: EBS 저장 데이터 암호화 (계정 기본 암호화) — 탐지 → 자동 조치(예방).
# 제자리 암호화가 불가한 경우(신규 볼륨만 암호화. 기존 볼륨 교정은 런북).
module "ebs_encryption_default" {
  source = "./modules/ebs-encryption-default"

  name_prefix       = var.project_name
  lambda_source_dir = local.ebs_enc_lambda_dir
  config_rule_name  = local.config_rules.ebs
  log_group_name    = aws_cloudwatch_log_group.remediation["ebs"].name
  log_group_arn     = aws_cloudwatch_log_group.remediation["ebs"].arn

  depends_on = [module.config_baseline, module.log_lake, module.dashboard]
}
