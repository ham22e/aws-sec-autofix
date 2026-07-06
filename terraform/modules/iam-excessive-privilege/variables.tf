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
