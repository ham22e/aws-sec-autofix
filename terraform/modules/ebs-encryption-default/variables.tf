variable "name_prefix" {
  description = "리소스 이름 접두사 (루트 project_name 전달)"
  type        = string
}

variable "lambda_source_dir" {
  description = "조치 Lambda 소스 디렉토리 경로 (handler.py 포함)"
  type        = string
}
