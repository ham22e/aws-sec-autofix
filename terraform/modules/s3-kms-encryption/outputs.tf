output "vulnerable_bucket" {
  description = "의도적 취약(SSE-S3 만, KMS 아님) S3 버킷 이름"
  value       = aws_s3_bucket.vulnerable.bucket
}

output "kms_key_arn" {
  description = "조치가 적용할 대상 KMS 키 ARN"
  value       = aws_kms_key.s3.arn
}

output "config_rule_name" {
  description = "S3 KMS 기본 암호화 탐지용 Config 규칙 이름"
  value       = aws_config_config_rule.s3_kms.name
}

output "lambda_function_name" {
  description = "조치 Lambda 함수 이름"
  value       = aws_lambda_function.remediation.function_name
}

output "event_rule_name" {
  description = "NON_COMPLIANT 트리거 EventBridge 규칙 이름"
  value       = aws_cloudwatch_event_rule.noncompliant.name
}
