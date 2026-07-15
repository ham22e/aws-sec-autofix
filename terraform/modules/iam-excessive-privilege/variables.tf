variable "name_prefix" {
  description = "리소스 이름 접두사 (루트 project_name 전달)"
  type        = string
}

variable "detect_lambda_source_dir" {
  description = "탐지·알림 Lambda 소스 디렉토리 경로 (handler.py 포함)"
  type        = string
}

variable "approve_lambda_source_dir" {
  description = "승인 조치 Lambda 소스 디렉토리 경로 (handler.py 포함)"
  type        = string
}

variable "alert_email" {
  description = "SNS 알림을 받을 이메일 주소. null 이면 이메일 구독을 만들지 않는다(토픽만 생성)."
  type        = string
  default     = null
}

variable "config_rule_name" {
  description = "이 시나리오의 AWS Config 규칙 이름. 루트가 소유해 EventBridge 패턴과 규칙에 함께 넘긴다."
  type        = string
}

variable "detect_log_group_name" {
  description = "탐지·알림 Lambda 의 로그 그룹 이름. 루트가 먼저 만들어 넘긴다."
  type        = string
}

variable "detect_log_group_arn" {
  description = "탐지·알림 Lambda 의 로그 그룹 ARN. 역할의 로그 쓰기 권한을 이 그룹으로만 좁힌다."
  type        = string
}

variable "approve_log_group_name" {
  description = "승인 조치 Lambda 의 로그 그룹 이름. 루트가 먼저 만들어 넘긴다."
  type        = string
}

variable "approve_log_group_arn" {
  description = "승인 조치 Lambda 의 로그 그룹 ARN. 역할의 로그 쓰기 권한을 이 그룹으로만 좁힌다."
  type        = string
}
