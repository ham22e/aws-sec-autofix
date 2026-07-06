# =====================================================================
# 가시화 (대시보드 / 타임라인), 횡단 운영/분석 계층
#
# 탐지→조치 시나리오가 아니라, 앞선 시나리오들이 남긴 조치 로그와 Config
# 준수 상태를 CloudWatch 대시보드로 "한눈에" 보여준다. 로그 레이크가
# 감사·장기 분석(Athena)을 담당한다면, 여기는 운영 현황 실시간 뷰다.
#
# 구성:
#  1) 조치 로그 그룹 5개 → metric filter → AutoFix/Remediation 메트릭(control·status)
#  2) Config 규칙 준수 상태 → (스케줄) 준수율 발행 Lambda → AutoFix/Compliance 메트릭
#  3) 위 메트릭 + Logs Insights 쿼리로 CloudWatch 대시보드 위젯 구성
#
# 조치 Lambda 코드는 변경하지 않는다. 기존 정규화 JSON 로그가 그대로 입력이 된다.
# =====================================================================

data "aws_region" "current" {}

locals {
  region = data.aws_region.current.region

  # Logs Insights 타임라인 위젯이 조회할 로그 그룹들을 SOURCE 절 체인으로 조립.
  # filter event_type="remediation" 이 조치 외 로그(플랫폼 노이즈 등)를 걸러낸다.
  timeline_sources = join(" | ", [for lg in var.remediation_log_group_names : "SOURCE '${lg}'"])
}

# --- 1. 조치 로그 → 메트릭 (metric filter) ----------------------------
# 각 조치 로그 그룹에 필터 1개. event_type=remediation 라인만 집계하고(플랫폼
# 노이즈 제외), control·status 를 차원으로 뽑아 AutoFix/Remediation 네임스페이스로 낸다.
# 차원(control·status)은 모든 조치 로그에 항상 존재하므로 누락 없이 발행된다.
resource "aws_cloudwatch_log_metric_filter" "remediation" {
  for_each = toset(var.remediation_log_group_names)

  name           = "${var.name_prefix}-remediation-event"
  log_group_name = each.value
  pattern        = "{ $.event_type = \"remediation\" }"

  metric_transformation {
    name      = "RemediationEvent"
    namespace = "AutoFix/Remediation"
    value     = "1"
    unit      = "Count"
    dimensions = {
      control = "$.control"
      status  = "$.status"
    }
  }
}

# --- 2. 준수율 발행 Lambda --------------------------------------------
data "archive_file" "compliance" {
  type = "zip"
  # 단일 파일 핸들러 → source_file 로 handler.py 만 담는다(로컬 __pycache__ 배제).
  source_file = "${var.compliance_lambda_source_dir}/handler.py"
  output_path = "${path.module}/build/compliance-metrics.zip"
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

resource "aws_iam_role" "compliance" {
  name               = "${var.name_prefix}-compliance-metrics-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_cloudwatch_log_group" "compliance" {
  name              = "/aws/lambda/${var.name_prefix}-compliance-metrics"
  retention_in_days = 14
}

# 최소 권한: Config 준수 상태 조회(읽기) + 지정 네임스페이스로만 메트릭 발행 + 로그.
# DescribeComplianceByConfigRule·PutMetricData 는 리소스 레벨 스코프를 지원하지
# 않아 resource="*" 이나, PutMetricData 는 cloudwatch:namespace 조건으로 좁힌다.
data "aws_iam_policy_document" "compliance" {
  statement {
    sid       = "ReadConfigCompliance"
    effect    = "Allow"
    actions   = ["config:DescribeComplianceByConfigRule"]
    resources = ["*"]
  }

  statement {
    sid       = "PublishComplianceMetrics"
    effect    = "Allow"
    actions   = ["cloudwatch:PutMetricData"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "cloudwatch:namespace"
      values   = ["AutoFix/Compliance"]
    }
  }

  statement {
    sid    = "WriteLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.compliance.arn}:*"]
  }
}

resource "aws_iam_role_policy" "compliance" {
  name   = "compliance-metrics"
  role   = aws_iam_role.compliance.id
  policy = data.aws_iam_policy_document.compliance.json
}

resource "aws_lambda_function" "compliance" {
  function_name    = "${var.name_prefix}-compliance-metrics"
  role             = aws_iam_role.compliance.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.compliance.output_path
  source_code_hash = data.archive_file.compliance.output_base64sha256
  timeout          = 30

  environment {
    variables = {
      # 준수율 계산 대상 규칙(콤마 구분). 루트가 시나리오 모듈 output 을 모아 전달.
      CONFIG_RULE_NAMES = join(",", var.config_rule_names)
    }
  }

  depends_on = [
    aws_iam_role_policy.compliance,
    aws_cloudwatch_log_group.compliance,
  ]
}

# 스케줄 트리거: 5분마다 준수율 스냅샷을 발행한다(Config 재평가 지연 고려).
resource "aws_cloudwatch_event_rule" "schedule" {
  name                = "${var.name_prefix}-compliance-metrics-schedule"
  description         = "준수율 발행 Lambda 를 주기 호출해 AutoFix/Compliance 메트릭을 갱신한다."
  schedule_expression = "rate(5 minutes)"
}

resource "aws_cloudwatch_event_target" "compliance" {
  rule      = aws_cloudwatch_event_rule.schedule.name
  target_id = "compliance-metrics-lambda"
  arn       = aws_lambda_function.compliance.arn
}

resource "aws_lambda_permission" "eventbridge" {
  statement_id  = "AllowEventBridgeInvoke"
  action        = "lambda:InvokeFunction"
  function_name = aws_lambda_function.compliance.function_name
  principal     = "events.amazonaws.com"
  source_arn    = aws_cloudwatch_event_rule.schedule.arn
}

# --- 3. CloudWatch 대시보드 ------------------------------------------
# 위젯 데이터 소스: metric filter 메트릭(조치) + 준수율 Lambda 메트릭(준수율) +
# Logs Insights(타임라인·집계). SEARCH 식으로 control·status 조합을 자동 수집한다.
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.name_prefix}-overview"

  dashboard_body = jsonencode({
    widgets = [
      # 준수율(%) 게이지
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 6
        height = 6
        properties = {
          title   = "준수율 (%)"
          region  = local.region
          view    = "gauge"
          stat    = "Maximum"
          period  = 300
          metrics = [["AutoFix/Compliance", "ComplianceRate"]]
          yAxis   = { left = { min = 0, max = 100 } }
        }
      },
      # 준수/미준수 규칙 수
      {
        type   = "metric"
        x      = 6
        y      = 0
        width  = 6
        height = 6
        properties = {
          # timeSeries 로 준수/미준수 개수 추이를 본다. singleValue+Maximum 은 조회창 안
          # 서로 다른 시점의 최댓값을 각각 잡아 "합이 안 맞는" 오해를 유발했다(조치 진행 중
          # 준수 0->1, 미준수 4->3). 추이 그래프는 그 변화를 그대로 보여준다.
          title  = "Config 규칙 준수/미준수 수 (추이)"
          region = local.region
          view   = "timeSeries"
          stat   = "Maximum"
          period = 300
          metrics = [
            ["AutoFix/Compliance", "CompliantRules", { label = "준수" }],
            ["AutoFix/Compliance", "NonCompliantRules", { label = "미준수" }],
          ]
        }
      },
      # 규칙별 준수 상태(1=준수, 0=미준수)
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          # SEARCH 인자에 Maximum 을 써서 0/1 상태선이 계단식으로 딱 떨어지게 한다.
          # (Average 는 전환 주기에 0 과 1 을 평균내 0.5 로 보였다. 위젯레벨 stat 은
          # 표현식 전용 위젯에선 무시되므로 두지 않는다.)
          title  = "규칙별 준수 상태 (1=준수, 0=미준수)"
          region = local.region
          view   = "timeSeries"
          period = 300
          metrics = [
            [{ expression = "SEARCH('{AutoFix/Compliance,ConfigRuleName} MetricName=\"RuleCompliance\"', 'Maximum', 300)", id = "rc" }]
          ]
          yAxis = { left = { min = 0, max = 1 } }
        }
      },
      # 조치 이벤트 (control·status별)
      # 참고: "총계" singleValue 타일은 제거했다. SUM(SEARCH(...))+singleValue 는 조회창
      # 전체 누적이 아니라 최근 한 period 값만 보여 "총계"를 과소 표기했다. 누적은 아래
      # 타임라인/집계 위젯이 정확히 담당한다. (위젯레벨 stat 은 표현식 전용이라 생략.)
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 24
        height = 6
        properties = {
          title   = "조치 이벤트 (control·status별)"
          region  = local.region
          view    = "bar"
          period  = 300
          stacked = false
          metrics = [
            [{ expression = "SEARCH('{AutoFix/Remediation,control,status} MetricName=\"RemediationEvent\"', 'Sum', 300)", id = "ev" }]
          ]
        }
      },
      # 조치 타임라인 (Logs Insights)
      {
        type   = "log"
        x      = 0
        y      = 12
        width  = 24
        height = 8
        properties = {
          title  = "조치 타임라인 (언제 무엇이 어떻게 조치됐나)"
          region = local.region
          view   = "table"
          query  = "${local.timeline_sources} | fields @timestamp, control, status, bucket, error_type | filter event_type = \"remediation\" | sort @timestamp desc | limit 50"
        }
      },
      # control x status 집계 (Logs Insights)
      {
        type   = "log"
        x      = 0
        y      = 20
        width  = 24
        height = 6
        properties = {
          title  = "control x status 집계"
          region = local.region
          view   = "table"
          query  = "${local.timeline_sources} | filter event_type = \"remediation\" | stats count(*) as events by control, status | sort control, status"
        }
      },
    ]
  })
}
