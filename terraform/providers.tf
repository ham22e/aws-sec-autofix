terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    archive = {
      source  = "hashicorp/archive"
      version = "~> 2.0"
    }
  }

  # 초기에는 로컬 백엔드를 사용한다(테스트 환경, terraform destroy 전제).
  # 원격 상태 백엔드는 선행 S3 버킷/DynamoDB 락 테이블이 필요하므로
  # 환경이 안정화된 뒤 아래 블록의 주석을 해제해 전환한다.
  # backend "s3" {
  #   bucket         = "<state-bucket-name>"
  #   key            = "autofix/terraform.tfstate"
  #   region         = "ap-northeast-2"
  #   dynamodb_table = "<state-lock-table-name>"
  #   encrypt        = true
  # }
}

provider "aws" {
  region  = var.aws_region
  profile = var.aws_profile

  default_tags {
    tags = var.default_tags
  }
}
