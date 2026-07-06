output "vulnerable_bucket" {
  description = "의도적 취약(퍼블릭) S3 버킷 이름"
  value       = aws_s3_bucket.vulnerable.bucket
}

output "config_rule_name" {
  description = "S3 퍼블릭 read 탐지용 Config 규칙 이름"
  value       = aws_config_config_rule.s3_public_read.name
}

output "lambda_function_name" {
  description = "조치 Lambda 함수 이름"
  value       = aws_lambda_function.remediation.function_name
}

output "event_rule_name" {
  description = "NON_COMPLIANT 트리거 EventBridge 규칙 이름"
  value       = aws_cloudwatch_event_rule.noncompliant.name
}
