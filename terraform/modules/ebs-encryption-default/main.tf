# =====================================================================
# 시나리오: EBS 저장 데이터 암호화 (계정 기본 암호화) — 탐지 → 자동 조치(예방)
#
# 흐름: 계정 EBS 기본 암호화 OFF (+ 태그된 미암호화 볼륨)
#        → Config 규칙 EC2_EBS_ENCRYPTION_BY_DEFAULT = NON_COMPLIANT (주기 트리거)
#        → EventBridge → 조치 Lambda(EnableEbsEncryptionByDefault) → COMPLIANT
#
# ⚠️ 이 시나리오는 "제자리 암호화가 불가능한" 경우다. 조치 Lambda 는 계정 기본
#    암호화를 켜서 "신규" 볼륨만 암호화되게 하는 예방 조치만 한다(비파괴).
#    기존 미암호화 볼륨을 실제 암호화하려면 스냅샷→암호화 복사→볼륨 재생성이
#    필요하고 파괴적(다운타임)이라 자동화하지 않는다.
#    (근거·기존 볼륨 교정 절차: docs/runbooks/ebs-encryption-default.md)
#
# ⚠️ EC2_EBS_ENCRYPTION_BY_DEFAULT 는 "주기(Periodic)" 규칙이다. 최초 평가나 조치
#    후 재평가를 즉시 보려면 `aws configservice start-config-rules-evaluation` 로
#    강제해야 한다(S3 변경 트리거 규칙과 다른 점).
#
# 이 규칙은 config-baseline 의 Recorder 가 있어야 평가된다.
# (루트 main.tf 에서 depends_on = [module.config_baseline] 로 순서 보장)
# =====================================================================

data "aws_availability_zones" "available" {
  state = "available"
}

# --- 의도적 취약 상태: 계정 EBS 기본 암호화 OFF ---------------------------
# 이 설정은 계정+리전 단위 설정이라 리소스 태그를 붙일 수 없다(Purpose 태그는
# 아래 볼륨에 부여). enabled=false 로 "의도적 취약(기본 암호화 꺼짐)" 상태를
# 명시적으로 고정한다. 조치 Lambda 가 이를 켜면 Terraform 드리프트가 생기는데,
# 이는 정상이며 재검증 시 `terraform apply` 로 다시 OFF 로 리셋된다(S3 퍼블릭 노출 BPA 와 동일).
# 참고) 이 리소스를 destroy 로 제거하면 기본 암호화가 자동 비활성화된다.
resource "aws_ebs_encryption_by_default" "this" {
  enabled = false
}

# 태그된 tangible 미암호화 볼륨 = "지금 저장 데이터가 암호화 안 된 상태"의 구체적 증거이자
# 기존 볼륨 교정(런북) 검증 대상. 기본 암호화가 꺼진 뒤에 만들어야 실제로 미암호화가 된다.
resource "aws_ebs_volume" "vulnerable" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1
  type              = "gp3"
  encrypted         = false

  tags = {
    Name    = "${var.name_prefix}-unencrypted"
    Purpose = "intentionally-vulnerable"
  }

  depends_on = [aws_ebs_encryption_by_default.this]
}

# --- 탐지: AWS Config 관리형 규칙 (주기) ------------------------------
# ⚠️ 이 규칙은 조치 배선(EventBridge 타깃 + Lambda 권한)이 완성된 뒤에 만들어야 한다.
# 주기 규칙이라도 생성 직후 한 번은 즉시 평가한다. 그 순간 타깃이 안 붙어 있으면
# NON_COMPLIANT 전환 이벤트가 그대로 사라진다(재생되지 않는다).
# 그래서 event_pattern 은 이 리소스를 참조하지 않고 var.config_rule_name 문자열을 쓴다.
# 리소스를 참조하면 Terraform 이 규칙을 먼저 만들어 경쟁 상태가 구조적으로 생긴다.
resource "aws_config_config_rule" "ebs_default" {
  name = var.config_rule_name

  source {
    owner             = "AWS"
    source_identifier = "EC2_EBS_ENCRYPTION_BY_DEFAULT"
  }

  # 주기 규칙의 자동 재평가 주기(테스트는 강제 평가로 즉시화하므로 최저 비용값 사용).
  maximum_execution_frequency = "TwentyFour_Hours"

  depends_on = [
    aws_cloudwatch_event_target.lambda,
    aws_lambda_permission.eventbridge,
  ]
}

# --- 조치 Lambda -------------------------------------------------------
data "archive_file" "lambda" {
  type = "zip"
  # 단일 파일 핸들러 → source_file 로 handler.py 만 담는다(로컬 __pycache__ 배제).
  source_file = "${var.lambda_source_dir}/handler.py"
  output_path = "${path.module}/build/ebs-encryption-default.zip"
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
  name               = "${var.name_prefix}-ebs-encryption-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# 최소 권한: EBS 기본 암호화 조회/활성화 + 로그.
# EnableEbsEncryptionByDefault·GetEbsEncryptionByDefault 는 계정+리전 단위 API 라
# 리소스 레벨 스코프를 지원하지 않는다 → resource="*" 불가피(계정 설정 조작만 가능).
data "aws_iam_policy_document" "lambda" {
  statement {
    sid    = "ManageAccountEbsEncryptionDefault"
    effect = "Allow"
    actions = [
      "ec2:GetEbsEncryptionByDefault",
      "ec2:EnableEbsEncryptionByDefault",
    ]
    resources = ["*"]
  }

  statement {
    sid    = "WriteLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${var.log_group_arn}:*"]
  }
}

resource "aws_iam_role_policy" "lambda" {
  name   = "ebs-encryption-default"
  role   = aws_iam_role.lambda.id
  policy = data.aws_iam_policy_document.lambda.json
}

resource "aws_lambda_function" "remediation" {
  function_name    = "${var.name_prefix}-ebs-encryption-default"
  role             = aws_iam_role.lambda.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.lambda.output_path
  source_code_hash = data.archive_file.lambda.output_base64sha256
  timeout          = 30

  depends_on = [
    aws_iam_role_policy.lambda,
  ]
}

# --- 연결: EventBridge (탐지 → 조치) -----------------------------------
resource "aws_cloudwatch_event_rule" "noncompliant" {
  name        = "${var.name_prefix}-ebs-encryption-noncompliant"
  description = "EBS 기본 암호화 규칙이 NON_COMPLIANT 로 바뀌면 조치 Lambda 를 트리거한다."

  event_pattern = jsonencode({
    source      = ["aws.config"]
    detail-type = ["Config Rules Compliance Change"]
    detail = {
      configRuleName = [var.config_rule_name]
      newEvaluationResult = {
        complianceType = ["NON_COMPLIANT"]
      }
    }
  })
}

resource "aws_cloudwatch_event_target" "lambda" {
  rule      = aws_cloudwatch_event_rule.noncompliant.name
  target_id = "ebs-encryption-default-lambda"
  arn       = aws_lambda_function.remediation.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.remediation.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.noncompliant.arn
}
