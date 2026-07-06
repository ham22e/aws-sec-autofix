output "vulnerable_policy_arn" {
  description = "의도적 과도 권한(admin) 고객관리형 정책 ARN. 승인 조치 대상."
  value       = aws_iam_policy.admin.arn
}

output "dummy_role_name" {
  description = "admin 정책이 부착된 더미(과도 권한) 역할 이름"
  value       = aws_iam_role.dummy.name
}

output "config_rule_name" {
  description = "IAM 과도 권한 탐지용 Config 규칙 이름"
  value       = aws_config_config_rule.iam_admin.name
}

output "detect_notify_lambda" {
  description = "탐지·알림 Lambda 함수 이름"
  value       = aws_lambda_function.detect_notify.function_name
}

output "approve_remediate_lambda" {
  description = "승인 조치 Lambda 함수 이름 (사람이 수동 invoke)"
  value       = aws_lambda_function.approve_remediate.function_name
}

output "sns_topic_arn" {
  description = "IAM 과도 권한 알림 SNS 토픽 ARN"
  value       = aws_sns_topic.alerts.arn
}
