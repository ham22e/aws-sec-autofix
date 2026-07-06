output "dashboard_name" {
  description = "탐지·조치 현황 CloudWatch 대시보드 이름"
  value       = aws_cloudwatch_dashboard.main.dashboard_name
}

output "dashboard_url" {
  description = "대시보드 콘솔 딥링크"
  value       = "https://${local.region}.console.aws.amazon.com/cloudwatch/home?region=${local.region}#dashboards/dashboard/${aws_cloudwatch_dashboard.main.dashboard_name}"
}

output "compliance_metrics_lambda" {
  description = "준수율(AutoFix/Compliance 메트릭) 발행 Lambda 함수 이름"
  value       = aws_lambda_function.compliance.function_name
}
