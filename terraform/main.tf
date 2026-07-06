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

  # 대시보드 준수율이 판정할 Config 규칙 이름들(각 시나리오 모듈이 만든 규칙과 1:1).
  config_rule_names = [
    module.s3_public_access.config_rule_name,
    module.iam_excessive_privilege.config_rule_name,
    module.s3_kms_encryption.config_rule_name,
    module.ebs_encryption_default.config_rule_name,
  ]

  # 로그 레이크가 중앙 수집할 조치 Lambda 로그 그룹 목록(이름이 결정적이라 여기서 조립).
  # 각 시나리오 모듈이 만든 로그 그룹과 1:1로 대응한다. 변환 Lambda 자신의 로그 그룹은
  # 순환(로그→Firehose→변환→로그)을 피하려 제외한다.
  remediation_log_group_names = [
    "/aws/lambda/${var.project_name}-s3-remediation",
    "/aws/lambda/${var.project_name}-iam-detect-notify",
    "/aws/lambda/${var.project_name}-iam-approve-remediate",
    "/aws/lambda/${var.project_name}-s3-kms-encryption",
    "/aws/lambda/${var.project_name}-ebs-encryption-default",
  ]
}

# 계정 싱글턴 Config 인프라. Recorder 가 계정+리전당 1개 제약이 있어
# 기존 Config 가 있으면 manage_config_baseline=false 로 끈다.
module "config_baseline" {
  count  = var.manage_config_baseline ? 1 : 0
  source = "./modules/config-baseline"

  name_prefix = var.project_name
}

# 시나리오: S3 퍼블릭 노출 (탐지 → 자동 조치).
module "s3_public_access" {
  source = "./modules/s3-public-access"

  name_prefix       = var.project_name
  lambda_source_dir = local.lambda_source_dir

  # Config 규칙이 평가되려면 Recorder 가 먼저 켜져 있어야 한다.
  depends_on = [module.config_baseline]
}

# 시나리오: IAM 과도 권한 (탐지 → 알림 → 승인 기반 조치).
# S3 와 달리 자동 조치하지 않는다(권한 자동 회수 = 서비스 중단 위험).
module "iam_excessive_privilege" {
  source = "./modules/iam-excessive-privilege"

  name_prefix               = var.project_name
  detect_lambda_source_dir  = local.iam_detect_lambda_dir
  approve_lambda_source_dir = local.iam_approve_lambda_dir
  alert_email               = var.alert_email

  # IAM 규칙은 글로벌 리소스 기록이 켜진 Recorder 가 있어야 평가된다.
  depends_on = [module.config_baseline]
}

# 시나리오: S3 저장 데이터 암호화 (KMS) — 탐지 → 자동 조치.
# 제자리 암호화가 가능한 경우(put-bucket-encryption 으로 SSE-KMS 적용).
module "s3_kms_encryption" {
  source = "./modules/s3-kms-encryption"

  name_prefix       = var.project_name
  lambda_source_dir = local.s3_kms_lambda_dir

  depends_on = [module.config_baseline]
}

# 시나리오: EBS 저장 데이터 암호화 (계정 기본 암호화) — 탐지 → 자동 조치(예방).
# 제자리 암호화가 불가한 경우(신규 볼륨만 암호화. 기존 볼륨 교정은 런북).
module "ebs_encryption_default" {
  source = "./modules/ebs-encryption-default"

  name_prefix       = var.project_name
  lambda_source_dir = local.ebs_enc_lambda_dir

  depends_on = [module.config_baseline]
}

# 로그 레이크 (로깅 통합), 횡단 운영/분석 계층.
# CloudTrail·VPC Flow Logs·조치 Lambda 로그를 하나의 S3 버킷에 모아 Athena 로 조회한다.
# 탐지→조치 시나리오가 아니라, 위 시나리오들이 남긴 로그를 수집·분석한다.
module "log_lake" {
  source = "./modules/log-lake"

  name_prefix                 = var.project_name
  processor_lambda_source_dir = local.log_lake_processor_dir
  remediation_log_group_names = local.remediation_log_group_names
  enable_cloudtrail           = var.enable_cloudtrail
  enable_vpc_flow_logs        = var.enable_vpc_flow_logs

  # 구독 필터가 참조하는 조치 로그 그룹이 먼저 존재해야 한다.
  depends_on = [
    module.s3_public_access,
    module.iam_excessive_privilege,
    module.s3_kms_encryption,
    module.ebs_encryption_default,
  ]
}

# 가시화 (대시보드 / 타임라인), 횡단 운영 계층.
# 조치 로그(metric filter)와 Config 준수 상태(발행 Lambda)를 CloudWatch 대시보드로
# 한눈에 보여준다. 로그 레이크가 감사·장기 분석이라면 여기는 운영 현황 실시간 뷰다.
module "dashboard" {
  source = "./modules/dashboard"

  name_prefix                  = var.project_name
  remediation_log_group_names  = local.remediation_log_group_names
  config_rule_names            = local.config_rule_names
  compliance_lambda_source_dir = local.compliance_metrics_dir

  # metric filter 대상 로그 그룹과 준수율 대상 Config 규칙이 먼저 존재해야 한다.
  depends_on = [
    module.config_baseline,
    module.s3_public_access,
    module.iam_excessive_privilege,
    module.s3_kms_encryption,
    module.ebs_encryption_default,
  ]
}
