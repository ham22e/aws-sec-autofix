# =====================================================================
# AWS Config 기반(baseline) — 탐지 엔진의 공용 인프라
#
# ⚠️ Config Configuration Recorder 는 "계정 + 리전당 1개"만 존재할 수 있다.
#    이미 다른 곳(조직 Config, 다른 스택 등)에서 Recorder 를 운영 중이면
#    루트에서 var.manage_config_baseline = false 로 이 모듈 전체를 끄고,
#    Config 규칙만 기존 Recorder 위에 생성해야 한다. (중복 생성 시 apply 실패)
#
# 이 모듈은 계정 싱글턴 자원이므로 시나리오(s3-public-access 등)와 분리해 둔다.
# IAM 과도 권한·미암호화 리소스 시나리오도 이 하나의 baseline 을 공유한다.
# =====================================================================

data "aws_caller_identity" "current" {}

# --- Config 스냅샷 전달용 S3 버킷 (Delivery Channel 대상) ---------------
resource "aws_s3_bucket" "config" {
  bucket_prefix = "${var.name_prefix}-config-"
  # 테스트 환경: destroy 시 Config 가 쌓은 스냅샷 객체까지 함께 정리한다.
  force_destroy = true

  tags = {
    Name = "${var.name_prefix}-config"
  }
}

resource "aws_s3_bucket_public_access_block" "config" {
  bucket = aws_s3_bucket.config.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# Config 서비스가 이 버킷에 스냅샷을 쓸 수 있도록 하는 표준 버킷 정책.
data "aws_iam_policy_document" "config_bucket" {
  statement {
    sid     = "AWSConfigBucketPermissionsCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    resources = [aws_s3_bucket.config.arn]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid     = "AWSConfigBucketExistenceCheck"
    effect  = "Allow"
    actions = ["s3:ListBucket"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    resources = [aws_s3_bucket.config.arn]
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }

  statement {
    sid     = "AWSConfigBucketDelivery"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.config.arn}/AWSLogs/${data.aws_caller_identity.current.account_id}/Config/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "AWS:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "config" {
  bucket = aws_s3_bucket.config.id
  policy = data.aws_iam_policy_document.config_bucket.json
}

# --- Config 서비스 역할 -------------------------------------------------
data "aws_iam_policy_document" "config_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["config.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "config" {
  name               = "${var.name_prefix}-config-role"
  assume_role_policy = data.aws_iam_policy_document.config_assume.json
}

# 리소스 상시 기록에 필요한 읽기 권한 + 전달 버킷 쓰기 권한을 담은 AWS 관리형
# 서비스 역할 정책. Config 가 모든 리소스 유형을 기록하려면 이 광범위한 읽기
# 권한이 필요하다(서비스 역할의 표준 구성).
resource "aws_iam_role_policy_attachment" "config_managed" {
  role       = aws_iam_role.config.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AWS_ConfigRole"
}

# --- Configuration Recorder + Delivery Channel -------------------------
resource "aws_config_configuration_recorder" "this" {
  name     = "${var.name_prefix}-recorder"
  role_arn = aws_iam_role.config.arn

  recording_group {
    all_supported = true
    # 전역(글로벌) 리소스(IAM 사용자·역할·그룹·고객관리형 정책) 기록.
    # IAM 과도 권한 규칙이 평가되려면 IAM 정책이 Config 에 기록돼야 하므로
    # 반드시 true 여야 한다. (false 면 IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS 가
    # 평가할 리소스가 없어 규칙이 동작하지 않는다.)
    #
    # 주의 1) 이 번들 옵션은 2022-02 이전에 AWS Config 가 제공된 리전에서만 글로벌
    #   IAM 리소스를 기록한다. 서울(ap-northeast-2)은 해당되어 정상 동작한다.
    # 주의 2) 글로벌 리소스는 중복 기록을 피하기 위해 계정 내 "한 리전에서만" 켜는 것을 권장.
    # 비용) Config 는 기록하는 '구성 항목(configuration item)' 개수로 과금된다. 이 옵션을
    #   켜면 계정의 IAM 리소스가 기록 대상에 들어와 항목 수가 늘고 요금이 소폭 오른다.
    #   테스트 계정은 IAM 리소스가 적어 증가폭은 미미하다(월 수 센트 수준).
    include_global_resource_types = true
  }
}

resource "aws_config_delivery_channel" "this" {
  name           = "${var.name_prefix}-channel"
  s3_bucket_name = aws_s3_bucket.config.bucket

  # PutDeliveryChannel 은 Config 가 버킷에 쓸 수 있는지(=버킷 정책 반영)를 생성 시점에
  # 검증한다. Recorder 와 버킷 정책이 모두 먼저 준비돼야 채널 생성이 안전하다.
  depends_on = [
    aws_config_configuration_recorder.this,
    aws_s3_bucket_policy.config,
  ]
}

# Recorder 를 실제로 켠다. 채널이 먼저 준비돼야 한다.
resource "aws_config_configuration_recorder_status" "this" {
  name       = aws_config_configuration_recorder.this.name
  is_enabled = true

  depends_on = [
    aws_config_delivery_channel.this,
    aws_s3_bucket_policy.config,
  ]
}
