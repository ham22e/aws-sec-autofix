variable "name_prefix" {
  description = "리소스 이름 접두사 (루트 project_name 전달)"
  type        = string
}

variable "remediation_log_group_names" {
  description = "metric filter·Logs Insights 위젯 대상 조치 Lambda CloudWatch 로그 그룹 이름 목록. 각 그룹당 metric filter 1개를 만든다."
  type        = list(string)
}

variable "config_rule_names" {
  description = "준수율 계산 대상 Config 규칙 이름 목록. 준수율 발행 Lambda 가 이 규칙들의 준수 상태를 읽어 메트릭으로 낸다. 루트에서 각 시나리오 모듈의 config_rule_name output 을 모아 전달."
  type        = list(string)
}

variable "compliance_lambda_source_dir" {
  description = "준수율 발행 Lambda 소스 디렉토리 (handler.py 포함)"
  type        = string
}
