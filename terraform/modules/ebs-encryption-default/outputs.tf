output "vulnerable_volume_id" {
  description = "의도적 미암호화 EBS 볼륨 ID (기존 볼륨 교정 검증 대상)"
  value       = aws_ebs_volume.vulnerable.id
}

output "config_rule_name" {
  description = "EBS 기본 암호화 탐지용 Config 규칙 이름"
  value       = aws_config_config_rule.ebs_default.name
}

output "lambda_function_name" {
  description = "조치 Lambda 함수 이름"
  value       = aws_lambda_function.remediation.function_name
}

output "event_rule_name" {
  description = "NON_COMPLIANT 트리거 EventBridge 규칙 이름"
  value       = aws_cloudwatch_event_rule.noncompliant.name
}
