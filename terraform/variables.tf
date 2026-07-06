variable "aws_region" {
  description = "리소스를 배포할 AWS 리전"
  type        = string
  default     = "ap-northeast-2"
}

variable "aws_profile" {
  description = "AWS CLI 자격증명 프로필 이름. null이면 환경변수(AWS_PROFILE 등)/기본 자격증명 체인을 따른다. 로컬 머신마다 다르므로 terraform.tfvars 등에서 지정한다."
  type        = string
  default     = null
}

variable "project_name" {
  description = "리소스 이름 접두사로 사용할 프로젝트 식별자"
  type        = string
  default     = "autofix"
}

variable "manage_config_baseline" {
  description = "AWS Config baseline(Recorder/Delivery Channel/역할/버킷)을 이 스택이 생성할지 여부. Configuration Recorder는 계정+리전당 1개만 가능하므로, 이미 다른 곳에서 Config를 운영 중이면 false로 두고 Config 규칙만 기존 Recorder 위에 생성한다."
  type        = bool
  default     = true
}

variable "alert_email" {
  description = "IAM 과도 권한 탐지 알림(SNS)을 받을 이메일 주소. null이면 이메일 구독을 만들지 않고 토픽만 생성한다(구독은 수신자 확인이 필요하므로 로컬마다 다름 → terraform.tfvars에서 지정)."
  type        = string
  default     = null
}

variable "enable_cloudtrail" {
  description = "로그 레이크가 CloudTrail 트레일을 생성할지 여부. 계정/조직에 이미 트레일이 있으면 false 로 두어 중복을 피한다."
  type        = bool
  default     = true
}

variable "enable_vpc_flow_logs" {
  description = "로그 레이크가 기본 VPC 대상 VPC Flow Logs 를 생성할지 여부. 기본 VPC 가 없는 계정이면 false 로 둔다."
  type        = bool
  default     = true
}

variable "default_tags" {
  description = "모든 리소스에 공통 적용할 태그. 의도적 취약 리소스의 Purpose 태그는 S3 퍼블릭 노출 시나리오에서 리소스별로 부여한다."
  type        = map(string)
  default = {
    Project   = "autofix"
    ManagedBy = "terraform"
  }
}
