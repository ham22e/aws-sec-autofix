# =====================================================================
# 시나리오: IAM 과도 권한 (CIEM) — 탐지 → 알림 → 승인 기반 조치
#
# 흐름: 의도적 과도 권한(고객관리형 admin 정책, Action:* Resource:*)
#        → Config 규칙 IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS = NON_COMPLIANT
#        → EventBridge → [탐지·알림 Lambda] SNS 알림 (정책 무변경)
#        ── (사람의 승인 게이트) ──
#        → [승인 조치 Lambda] 사람이 수동 invoke 해야만 정책 라이트사이징 → COMPLIANT
#
# ⚠️ S3 와 달리 IAM 은 자동 조치하지 않는다. 권한을 자동 회수하면 정당한
#    워크로드·운영자 접근이 끊겨 서비스 중단(사실상 self-inflicted DoS)이 되므로,
#    탐지·알림은 자동으로 하되 실제 권한 변경은 사람 승인 후에만 수행한다.
#    (근거: docs/runbooks/iam-excessive-privilege.md)
#
# 전제) 이 규칙은 IAM(글로벌 리소스)이 Config 에 기록돼야 평가된다.
#    config-baseline 의 recording_group.include_global_resource_types = true 필요.
#    (루트 main.tf 에서 depends_on = [module.config_baseline] 로 순서 보장)
# =====================================================================

# --- 의도적 과도 권한(admin) 정책 -------------------------------------
# Action:"*" + Resource:"*" 를 담은 고객관리형 정책 = 취약점의 핵심.
# 규칙은 "고객관리형 정책의 기본 버전"을 평가하므로 인라인/AWS관리형이 아닌
# 이 방식으로 만들어야 탐지된다.
data "aws_iam_policy_document" "admin" {
  statement {
    sid       = "IntentionallyOverbroadAdmin"
    effect    = "Allow"
    actions   = ["*"]
    resources = ["*"]
  }
}

resource "aws_iam_policy" "admin" {
  name_prefix = "${var.name_prefix}-admin-"
  description = "테스트용 의도적 과도 권한 정책 (Action:* Resource:*). 조치 대상."
  policy      = data.aws_iam_policy_document.admin.json

  tags = {
    Name    = "${var.name_prefix}-admin"
    Purpose = "intentionally-vulnerable"
  }
}

# --- 더미 역할 + admin 정책 부착 --------------------------------------
# 정책을 실제 주체에 부착해 "이 과도 권한이 누구에게 부여됐는가"(영향 주체)를
# 알림에서 구체적으로 보여줄 수 있게 한다. EC2 인스턴스 역할에 admin 을 붙인
# 전형적 과도 권한 상황을 모사한다.
data "aws_iam_policy_document" "dummy_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "dummy" {
  name_prefix        = "${var.name_prefix}-overprivileged-"
  assume_role_policy = data.aws_iam_policy_document.dummy_assume.json

  tags = {
    Name    = "${var.name_prefix}-overprivileged"
    Purpose = "intentionally-vulnerable"
  }
}

resource "aws_iam_role_policy_attachment" "dummy_admin" {
  role       = aws_iam_role.dummy.name
  policy_arn = aws_iam_policy.admin.arn
}

# --- 탐지: AWS Config 관리형 규칙 --------------------------------------
# 고객관리형 정책의 기본 버전에 Effect:Allow + Action:* + Resource:* 문이
# 있으면 NON_COMPLIANT. 계정의 모든 고객관리형 정책을 평가한다.
#
# ⚠️ 이 규칙은 알림 배선(EventBridge 타깃 + Lambda 권한)이 완성된 뒤에 만들어야 한다.
# Config 는 규칙이 생성되는 즉시 첫 평가를 돌리는데, 그 순간 타깃이 안 붙어 있으면
# NON_COMPLIANT 전환 이벤트가 그대로 사라진다(이벤트는 재생되지 않는다. 규칙이 이미
# NON_COMPLIANT 에 "머물러" 있어 새 전환이 생기지 않기 때문).
# 그래서 event_pattern 은 이 리소스를 참조하지 않고 var.config_rule_name 문자열을 쓴다.
# 리소스를 참조하면 Terraform 이 규칙을 먼저 만들어 경쟁 상태가 구조적으로 생긴다.
resource "aws_config_config_rule" "iam_admin" {
  name = var.config_rule_name

  source {
    owner             = "AWS"
    source_identifier = "IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS"
  }

  depends_on = [
    aws_cloudwatch_event_target.detect_notify,
    aws_lambda_permission.eventbridge,
  ]
}

# --- 알림 채널: SNS ----------------------------------------------------
resource "aws_sns_topic" "alerts" {
  name = "${var.name_prefix}-iam-alerts"
}

# 이메일 구독은 선택. alert_email 이 주어질 때만 만든다.
# (이메일 구독은 수신자가 콘솔/메일에서 구독을 "확인"해야 실제로 활성화된다.)
resource "aws_sns_topic_subscription" "email" {
  count = var.alert_email == null ? 0 : 1

  topic_arn = aws_sns_topic.alerts.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

# --- 공용: Lambda 신뢰 정책 -------------------------------------------
data "aws_iam_policy_document" "lambda_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["lambda.amazonaws.com"]
    }
  }
}

# =====================================================================
# 탐지·알림 Lambda (자동 트리거). 정책을 변경하지 않고 알림만 보낸다.
# =====================================================================
data "archive_file" "detect_notify" {
  type = "zip"
  # 핸들러는 단일 파일이라 source_file 로 handler.py 만 담는다. source_dir 로 디렉토리를
  # 통째로 담으면 로컬에서 생긴 __pycache__/*.pyc 까지 들어가 zip 해시가 비결정적이 된다.
  source_file = "${var.detect_lambda_source_dir}/handler.py"
  output_path = "${path.module}/build/detect-notify.zip"
}

resource "aws_iam_role" "detect_notify" {
  name               = "${var.name_prefix}-iam-detect-notify-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# 최소 권한: SNS 발행 + (알림 enrich 용) 테스트 정책 읽기 + 로그.
# 정책을 변경하는 권한은 부여하지 않는다 = 탐지·통지자.
data "aws_iam_policy_document" "detect_notify" {
  statement {
    sid       = "PublishAlerts"
    effect    = "Allow"
    actions   = ["sns:Publish"]
    resources = [aws_sns_topic.alerts.arn]
  }

  statement {
    sid     = "ListTargetPolicyEntitiesForEnrichment"
    effect  = "Allow"
    actions = ["iam:ListEntitiesForPolicy"]
    # 알림 본문에 "이 admin 정책이 누구에게 부착됐는가"(영향 주체/blast radius)를
    # 채우기 위한 읽기 전용 권한. Config 이벤트는 정책 ID 만 주므로 ARN 은 배포 시점에
    # 아는 테스트 정책 ARN(환경변수)으로 조회한다. 테스트 정책 ARN 에만 한정.
    resources = [aws_iam_policy.admin.arn]
  }

  statement {
    sid    = "WriteLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${var.detect_log_group_arn}:*"]
  }
}

resource "aws_iam_role_policy" "detect_notify" {
  name   = "iam-detect-notify"
  role   = aws_iam_role.detect_notify.id
  policy = data.aws_iam_policy_document.detect_notify.json
}

resource "aws_lambda_function" "detect_notify" {
  function_name    = "${var.name_prefix}-iam-detect-notify"
  role             = aws_iam_role.detect_notify.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.detect_notify.output_path
  source_code_hash = data.archive_file.detect_notify.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      SNS_TOPIC_ARN = aws_sns_topic.alerts.arn
      # 알림 본문에 "승인 조치는 이 함수를 invoke 하라"고 안내하기 위한 이름.
      APPROVE_FUNCTION_NAME = aws_lambda_function.approve_remediate.function_name
      # Config 이벤트는 정책 ID 만 주므로, enrich(부착 주체 조회)와 승인 안내에 쓸
      # 테스트 대상 정책 ARN 을 배포 시점 값으로 넘긴다.
      VULNERABLE_POLICY_ARN = aws_iam_policy.admin.arn
    }
  }

  depends_on = [
    aws_iam_role_policy.detect_notify,
  ]
}

# --- 연결: EventBridge (탐지 → 알림) ----------------------------------
resource "aws_cloudwatch_event_rule" "iam_noncompliant" {
  name        = "${var.name_prefix}-iam-admin-noncompliant"
  description = "IAM 과도 권한 규칙이 NON_COMPLIANT 로 바뀌면 탐지·알림 Lambda 를 트리거한다."

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

resource "aws_cloudwatch_event_target" "detect_notify" {
  rule      = aws_cloudwatch_event_rule.iam_noncompliant.name
  target_id = "iam-detect-notify-lambda"
  arn       = aws_lambda_function.detect_notify.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.detect_notify.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.iam_noncompliant.arn
}

# =====================================================================
# 승인 조치 Lambda (자동 트리거 없음 — EventBridge 에 연결하지 않는다).
# 사람이 confirm:true 로 수동 invoke 해야만 정책을 라이트사이징한다.
# =====================================================================
data "archive_file" "approve_remediate" {
  type = "zip"
  # 단일 파일 핸들러 → source_file 로 handler.py 만 담는다(위 detect_notify 와 동일 이유).
  source_file = "${var.approve_lambda_source_dir}/handler.py"
  output_path = "${path.module}/build/approve-remediate.zip"
}

resource "aws_iam_role" "approve_remediate" {
  name               = "${var.name_prefix}-iam-approve-remediate-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

# 최소 권한: 정책 버전 조작을 "테스트 정책 ARN 에만" 허용한다. 알림이 다른 정책을
# 가리켜도 자동 라이트사이징 대상은 이 정책으로 한정된다(blast radius 축소).
data "aws_iam_policy_document" "approve_remediate" {
  statement {
    sid    = "RightsizeTargetPolicy"
    effect = "Allow"
    actions = [
      "iam:GetPolicy",
      "iam:GetPolicyVersion",
      "iam:ListPolicyVersions",
      "iam:CreatePolicyVersion",
      "iam:DeletePolicyVersion",
    ]
    resources = [aws_iam_policy.admin.arn]
  }

  statement {
    sid    = "WriteLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${var.approve_log_group_arn}:*"]
  }
}

resource "aws_iam_role_policy" "approve_remediate" {
  name   = "iam-approve-remediate"
  role   = aws_iam_role.approve_remediate.id
  policy = data.aws_iam_policy_document.approve_remediate.json
}

resource "aws_lambda_function" "approve_remediate" {
  function_name    = "${var.name_prefix}-iam-approve-remediate"
  role             = aws_iam_role.approve_remediate.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.approve_remediate.output_path
  source_code_hash = data.archive_file.approve_remediate.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      # payload 에 policy_arn 을 생략하면 이 테스트 정책을 대상으로 삼는다. IAM 권한도
      # 이 ARN 에만 있으므로 다른 정책을 넘겨도 조작은 테스트 정책으로 한정된다.
      DEFAULT_POLICY_ARN = aws_iam_policy.admin.arn
    }
  }

  depends_on = [
    aws_iam_role_policy.approve_remediate,
  ]
}
