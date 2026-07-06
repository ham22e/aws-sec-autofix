# =====================================================================
# 시나리오: S3 저장 데이터 암호화 (KMS) — 탐지 → 자동 조치
#
# 흐름: 취약 버킷(SSE-S3=AES256 만, KMS 아님)
#        → Config 규칙 S3_DEFAULT_ENCRYPTION_KMS = NON_COMPLIANT (변경 트리거)
#        → EventBridge → 조치 Lambda(put-bucket-encryption 으로 SSE-KMS 적용) → COMPLIANT
#
# 이 시나리오는 "제자리 암호화가 가능한" 경우다. 조치 자체가 버킷 암호화 구성
# 변경이라 Config 가 자동 재평가하여 COMPLIANT 로 닫힌다(강제 평가 불필요).
# 비파괴: 기존 객체는 그대로, 신규 객체부터 KMS 로 암호화된다.
#
# 이 규칙은 config-baseline 의 Recorder 가 있어야 평가된다.
# (루트 main.tf 에서 depends_on = [module.config_baseline] 로 순서 보장)
# =====================================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# --- 조치가 적용할 대상 KMS 키 (고객관리형) --------------------------------
# 키 정책: 계정 root 관리 + S3 서비스 경유(kms:ViaService) 사용 허용.
data "aws_iam_policy_document" "s3_kms" {
  statement {
    sid    = "EnableRootAccountAdmin"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  # S3 가 이 계정의 요청을 대신해 키를 사용(객체 암호화)할 수 있게 한다.
  statement {
    sid    = "AllowS3UseOfKey"
    effect = "Allow"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:Decrypt",
      "kms:GenerateDataKey*",
      "kms:DescribeKey",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["s3.${data.aws_region.current.region}.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
  }
}

resource "aws_kms_key" "s3" {
  description             = "테스트용 S3 기본 암호화 대상 KMS 키 (조치 Lambda 가 버킷에 적용)."
  deletion_window_in_days = 7
  enable_key_rotation     = true
  policy                  = data.aws_iam_policy_document.s3_kms.json

  tags = {
    Name = "${var.name_prefix}-s3-kms"
  }
}

resource "aws_kms_alias" "s3" {
  name          = "alias/${var.name_prefix}-s3"
  target_key_id = aws_kms_key.s3.key_id
}

# --- 의도적 취약 버킷: SSE-S3(AES256) 만 = KMS 아님 -----------------------
resource "aws_s3_bucket" "vulnerable" {
  bucket_prefix = "${var.name_prefix}-unencrypted-"
  # 테스트 환경: destroy 시 버킷 내 객체까지 정리한다.
  force_destroy = true

  tags = {
    Name    = "${var.name_prefix}-unencrypted"
    Purpose = "intentionally-vulnerable"
  }
}

# 이 시나리오는 "암호화"만 다룬다. 퍼블릭 노출로 S3 시나리오 규칙에 걸리지 않도록
# BPA 4종을 켜 둔다(비-퍼블릭 유지).
resource "aws_s3_bucket_public_access_block" "vulnerable" {
  bucket = aws_s3_bucket.vulnerable.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# 취약점의 핵심: 기본 암호화를 SSE-S3(AES256)로 명시 고정 = KMS 아님.
# (KMS 규칙 S3_DEFAULT_ENCRYPTION_KMS 에는 NON_COMPLIANT. 조치 Lambda 가 이 설정을
#  aws:kms 로 교체하면 COMPLIANT 로 전환된다.)
resource "aws_s3_bucket_server_side_encryption_configuration" "vulnerable" {
  bucket = aws_s3_bucket.vulnerable.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# --- 탐지: AWS Config 관리형 규칙 --------------------------------------
# S3_DEFAULT_ENCRYPTION_KMS 는 계정의 모든 버킷을 평가할 수 있으나, 조치 대상과
# blast radius 를 테스트 버킷 하나로 한정하기 위해 이 버킷으로 scope 를 좁힌다.
# (좁히지 않으면 Config 전달 버킷·S3 시나리오 버킷 등도 KMS 아님으로 NON_COMPLIANT 가
#  되어 조치 Lambda 가 그것들까지 건드리게 된다.)
resource "aws_config_config_rule" "s3_kms" {
  name = "${var.name_prefix}-s3-default-encryption-kms"

  source {
    owner             = "AWS"
    source_identifier = "S3_DEFAULT_ENCRYPTION_KMS"
  }

  scope {
    compliance_resource_types = ["AWS::S3::Bucket"]
    compliance_resource_id    = aws_s3_bucket.vulnerable.id
  }
}

# --- 조치 Lambda -------------------------------------------------------
data "archive_file" "lambda" {
  type = "zip"
  # 단일 파일 핸들러 → source_file 로 handler.py 만 담는다(로컬 __pycache__ 배제,
  # zip 해시 결정성 유지).
  source_file = "${var.lambda_source_dir}/handler.py"
  output_path = "${path.module}/build/s3-kms-encryption.zip"
}

data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "lambda" {
  name               = "${var.name_prefix}-s3-kms-remediation-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.name_prefix}-s3-kms-encryption"
  retention_in_days = 14
}

# 최소 권한: 조치는 이 취약 버킷에만, 로그는 이 로그 그룹에만.
# put-bucket-encryption 은 호출자에게 KMS 권한을 요구하지 않는다(키 사용 인가는 키 정책의
# AllowS3UseOfKey 로 처리). 따라서 이 역할에는 kms 권한을 주지 않는다.
data "aws_iam_policy_document" "lambda" {
  statement {
    sid    = "RemediateTargetBucketEncryption"
    effect = "Allow"
    actions = [
      "s3:GetEncryptionConfiguration",
      "s3:PutEncryptionConfiguration",
    ]
    resources = [aws_s3_bucket.vulnerable.arn]
  }

  statement {
    sid    = "WriteLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.lambda.arn}:*"]
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "s3-kms-encryption"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

resource "aws_lambda_function" "remediation" {
  function_name    = "${var.name_prefix}-s3-kms-encryption"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      KMS_KEY_ARN = aws_kms_key.s3.arn
      # 이벤트에서 버킷을 특정하지 못할 때 사용할 대상 버킷.
      TARGET_BUCKET = aws_s3_bucket.vulnerable.bucket
    }
  }

  depends_on = [
    aws_iam_role_policy.lambda,
    aws_cloudwatch_log_group.lambda,
  ]
}

# --- 연결: EventBridge (탐지 → 조치) -----------------------------------
resource "aws_cloudwatch_event_rule" "noncompliant" {
  name        = "${var.name_prefix}-s3-kms-noncompliant"
  description = "S3 KMS 암호화 규칙이 NON_COMPLIANT 로 바뀌면 조치 Lambda 를 트리거한다."

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      configRuleName = [aws_config_config_rule.s3_kms.name]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.noncompliant.name
  target_id = "s3-kms-encryption-lambda"
  arn       = aws_lambda_function.remediation.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.noncompliant.arn
}
