variable "name_prefix" {
  description = "리소스 이름 접두사 (루트 project_name 전달)"
  type        = string
}

variable "lambda_source_dir" {
  description = "조치 Lambda 소스 디렉토리 경로 (handler.py 포함)"
  type        = string
}

variable "config_rule_name" {
  description = "이 시나리오의 AWS Config 규칙 이름. 루트가 소유해 EventBridge 패턴과 규칙에 함께 넘긴다."
  type        = string
}

variable "log_group_name" {
  description = "조치 Lambda 의 CloudWatch 로그 그룹 이름. 루트가 먼저 만들어 넘긴다(metric/구독 필터가 먼저 걸려야 첫 조치가 집계된다)."
  type        = string
}

variable "log_group_arn" {
  description = "조치 Lambda 의 CloudWatch 로그 그룹 ARN. Lambda 역할의 로그 쓰기 권한을 이 그룹으로만 좁힌다."
  type        = string
}
