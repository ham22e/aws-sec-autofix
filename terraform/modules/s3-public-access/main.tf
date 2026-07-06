# =====================================================================
# 시나리오: S3 퍼블릭 노출 (탐지 → 자동 조치)
#
# 흐름: 의도적 취약 버킷(BPA off + 퍼블릭 read 정책)
#        → Config 규칙 S3_BUCKET_PUBLIC_READ_PROHIBITED = NON_COMPLIANT
#        → EventBridge → 조치 Lambda(BPA 4종 강제) → COMPLIANT
#
# 이 규칙은 config-baseline 의 Recorder 가 있어야 평가된다.
# (루트 main.tf 에서 depends_on = [module.config_baseline] 로 순서 보장)
# =====================================================================

# --- 의도적 취약 S3 버킷 -----------------------------------------------
resource "aws_s3_bucket" "vulnerable" {
  bucket_prefix = "${var.name_prefix}-public-"
  # 테스트 환경: destroy 시 버킷 내 객체까지 정리한다.
  force_destroy = true

  tags = {
    Name    = "${var.name_prefix}-public"
    Purpose = "intentionally-vulnerable"
  }
}

# BPA 4종을 모두 해제한다 = 취약점의 핵심. (조치 Lambda 가 되돌릴 대상)
resource "aws_s3_bucket_public_access_block" "vulnerable" {
  bucket = aws_s3_bucket.vulnerable.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# 퍼블릭 read 를 실제로 허용하는 버킷 정책.
# BPA 해제만으로는 Config 규칙이 NON_COMPLIANT 가 되지 않으므로 정책이 필요하다.
data "aws_iam_policy_document" "public_read" {
  statement {
    sid       = "PublicReadGetObject"
    effect    = "Allow"
    actions   = ["s3:GetObject"]
    resources = ["${aws_s3_bucket.vulnerable.arn}/*"]

    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
  }
}

resource "aws_s3_bucket_policy" "public_read" {
  bucket = aws_s3_bucket.vulnerable.id
  policy = data.aws_iam_policy_document.public_read.json

  # BlockPublicPolicy 가 먼저 false 로 적용돼야 퍼블릭 정책이 수락된다.
  depends_on = [aws_s3_bucket_public_access_block.vulnerable]
}

# --- 탐지: AWS Config 관리형 규칙 --------------------------------------
resource "aws_config_config_rule" "s3_public_read" {
  name = "${var.name_prefix}-s3-bucket-public-read-prohibited"

  source {
    owner             = "AWS"
    source_identifier = "S3_BUCKET_PUBLIC_READ_PROHIBITED"
  }
}

# --- 조치 Lambda -------------------------------------------------------
data "archive_file" "lambda" {
  type        = "zip"
  source_dir  = var.lambda_source_dir
  output_path = "${path.module}/build/s3-remediation.zip"
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
  name               = "${var.name_prefix}-s3-remediation-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_cloudwatch_log_group" "lambda" {
  name              = "/aws/lambda/${var.name_prefix}-s3-remediation"
  retention_in_days = 14
}

# 최소 권한: 조치는 이 취약 버킷에만, 로그는 이 로그 그룹에만.
data "aws_iam_policy_document" "lambda" {
  statement {
    sid    = "RemediateTargetBucketBPA"
    effect = "Allow"
    actions = [
      "s3:GetBucketPublicAccessBlock",
      "s3:PutBucketPublicAccessBlock",
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
  name   = "s3-remediation"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

resource "aws_lambda_function" "remediation" {
  function_name    = "${var.name_prefix}-s3-remediation"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 30

  depends_on = [
    aws_iam_role_policy.lambda,
    aws_cloudwatch_log_group.lambda,
  ]
}

# --- 연결: EventBridge (탐지 → 조치) -----------------------------------
resource "aws_cloudwatch_event_rule" "noncompliant" {
  name        = "${var.name_prefix}-s3-public-read-noncompliant"
  description = "S3 퍼블릭 read 규칙이 NON_COMPLIANT 로 바뀌면 조치 Lambda 를 트리거한다."

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      configRuleName = [aws_config_config_rule.s3_public_read.name]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.noncompliant.name
  target_id = "s3-remediation-lambda"
  arn       = aws_lambda_function.remediation.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.noncompliant.arn
}
