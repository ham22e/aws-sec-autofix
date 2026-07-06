output "config_recorder_name" {
  description = "Configuration Recorder 이름 (baseline 미관리 시 null)"
  value       = var.manage_config_baseline ? module.config_baseline[0].recorder_name : null
}

output "vulnerable_bucket" {
  description = "의도적 취약(퍼블릭) S3 버킷 이름"
  value       = module.s3_public_access.vulnerable_bucket
}

output "config_rule_name" {
  description = "S3 퍼블릭 read 탐지용 Config 규칙 이름"
  value       = module.s3_public_access.config_rule_name
}

output "lambda_function_name" {
  description = "조치 Lambda 함수 이름"
  value       = module.s3_public_access.lambda_function_name
}

# --- IAM 과도 권한 시나리오 ---------------------------------
output "iam_vulnerable_policy_arn" {
  description = "의도적 과도 권한(admin) 정책 ARN. 승인 조치 Lambda invoke 시 사용."
  value       = module.iam_excessive_privilege.vulnerable_policy_arn
}

output "iam_dummy_role_name" {
  description = "admin 정책이 부착된 더미(과도 권한) 역할 이름"
  value       = module.iam_excessive_privilege.dummy_role_name
}

output "iam_config_rule_name" {
  description = "IAM 과도 권한 탐지용 Config 규칙 이름"
  value       = module.iam_excessive_privilege.config_rule_name
}

output "iam_detect_notify_lambda" {
  description = "IAM 탐지·알림 Lambda 함수 이름"
  value       = module.iam_excessive_privilege.detect_notify_lambda
}

output "iam_approve_remediate_lambda" {
  description = "IAM 승인 조치 Lambda 함수 이름 (사람이 수동 invoke)"
  value       = module.iam_excessive_privilege.approve_remediate_lambda
}

output "iam_sns_topic_arn" {
  description = "IAM 과도 권한 알림 SNS 토픽 ARN"
  value       = module.iam_excessive_privilege.sns_topic_arn
}

# --- 미암호화 리소스 (저장 데이터 암호화) 시나리오 -----------
output "s3_kms_vulnerable_bucket" {
  description = "의도적 취약(SSE-S3 만, KMS 아님) S3 버킷 이름"
  value       = module.s3_kms_encryption.vulnerable_bucket
}

output "s3_kms_key_arn" {
  description = "S3 조치가 적용할 대상 KMS 키 ARN"
  value       = module.s3_kms_encryption.kms_key_arn
}

output "s3_kms_config_rule_name" {
  description = "S3 KMS 기본 암호화 탐지용 Config 규칙 이름"
  value       = module.s3_kms_encryption.config_rule_name
}

output "s3_kms_lambda_function_name" {
  description = "S3 KMS 암호화 조치 Lambda 함수 이름"
  value       = module.s3_kms_encryption.lambda_function_name
}

output "ebs_vulnerable_volume_id" {
  description = "의도적 미암호화 EBS 볼륨 ID (기존 볼륨 교정 검증 대상)"
  value       = module.ebs_encryption_default.vulnerable_volume_id
}

output "ebs_config_rule_name" {
  description = "EBS 기본 암호화 탐지용 Config 규칙 이름"
  value       = module.ebs_encryption_default.config_rule_name
}

output "ebs_lambda_function_name" {
  description = "EBS 기본 암호화 조치 Lambda 함수 이름"
  value       = module.ebs_encryption_default.lambda_function_name
}

# --- 로그 레이크 (로깅 통합) --------------------------------
output "log_lake_bucket" {
  description = "세 소스 로그가 모이는 S3 로그 레이크 버킷 이름"
  value       = module.log_lake.lake_bucket
}

output "log_lake_glue_database" {
  description = "Athena 조회용 Glue 데이터베이스 이름"
  value       = module.log_lake.glue_database_name
}

output "log_lake_athena_workgroup" {
  description = "조치 이력 분석용 Athena 작업 그룹 이름"
  value       = module.log_lake.athena_workgroup
}

output "log_lake_cloudtrail_name" {
  description = "생성된 CloudTrail 트레일 이름 (enable_cloudtrail=false 면 null)"
  value       = module.log_lake.cloudtrail_name
}

output "log_lake_firehose_stream" {
  description = "조치 로그 수집 Firehose 스트림 이름"
  value       = module.log_lake.firehose_stream_name
}

# --- 가시화 (대시보드 / 타임라인) ---------------------------
output "dashboard_name" {
  description = "탐지·조치 현황 CloudWatch 대시보드 이름"
  value       = module.dashboard.dashboard_name
}

output "dashboard_url" {
  description = "대시보드 콘솔 딥링크"
  value       = module.dashboard.dashboard_url
}

output "compliance_metrics_lambda" {
  description = "준수율 메트릭 발행 Lambda 함수 이름"
  value       = module.dashboard.compliance_metrics_lambda
}
