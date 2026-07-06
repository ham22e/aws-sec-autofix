variable "name_prefix" {
  description = "리소스 이름 접두사 (루트 project_name 전달)"
  type        = string
}

variable "processor_lambda_source_dir" {
  description = "Firehose 봉투 제거 변환 Lambda 소스 디렉토리 (handler.py 포함)"
  type        = string
}

variable "remediation_log_group_names" {
  description = "로그 레이크로 중앙 수집할 조치 Lambda CloudWatch 로그 그룹 이름 목록. 각 그룹당 Firehose 구독 필터 1개를 만든다."
  type        = list(string)
}

variable "enable_cloudtrail" {
  description = "이 스택이 CloudTrail 트레일을 생성할지 여부. 계정/조직에 이미 트레일이 있으면 false 로 두어 중복을 피한다(관리형 Config baseline 스위치와 동일한 취지)."
  type        = bool
  default     = true
}

variable "enable_vpc_flow_logs" {
  description = "기본 VPC 대상 VPC Flow Logs 를 생성할지 여부. 기본 VPC 가 없는 계정이면 false 로 둔다."
  type        = bool
  default     = true
}
