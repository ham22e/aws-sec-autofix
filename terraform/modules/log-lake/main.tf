# =====================================================================
# 로그 레이크 (로깅 통합) 운영/분석 계층
#
# 흐름: 세 소스를 하나의 S3 버킷에 프리픽스로 분리 적재 → Glue 테이블 → Athena.
#   1) CloudTrail(관리 이벤트)   → AWSLogs/<acct>/CloudTrail/...
#   2) VPC Flow Logs(기본 VPC)   → vpc-flow/AWSLogs/<acct>/vpcflowlogs/...
#   3) 조치 Lambda 로그(5개)      → remediation/...
#        CloudWatch Logs → 구독필터 → Firehose(봉투 제거 변환 Lambda) → S3
#
# 이 모듈은 탐지→조치 시나리오가 아니라 횡단 인프라다(취약 리소스/Config 규칙 없음).
# 저장·분석은 Security Lake 대신 S3+Athena 로 구성(테스트 비용·destroy 용이).
# =====================================================================

data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  region     = data.aws_region.current.region
  # Glue 데이터베이스 이름은 하이픈 불가 → 언더스코어로 치환.
  glue_db_name = "${replace(var.name_prefix, "-", "_")}_log_lake"
  # CloudTrail 이 쓰는 표준 경로(버킷 정책 SourceArn 조건에 사용, 순환참조 회피용 문자열).
  trail_arn = "arn:aws:cloudtrail:${local.region}:${local.account_id}:trail/${var.name_prefix}-trail"
}

# =====================================================================
# 1. S3 로그 레이크 버킷
# =====================================================================
resource "aws_s3_bucket" "lake" {
  bucket_prefix = "${var.name_prefix}-log-lake-"
  # 테스트 환경: destroy 시 쌓인 로그 객체까지 함께 정리한다.
  force_destroy = true

  tags = {
    Name = "${var.name_prefix}-log-lake"
  }
}

resource "aws_s3_bucket_public_access_block" "lake" {
  bucket = aws_s3_bucket.lake.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_server_side_encryption_configuration" "lake" {
  bucket = aws_s3_bucket.lake.id

  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# 버킷 정책: CloudTrail·VPC Flow Logs 서비스가 이 버킷에 쓸 수 있게 한다.
# (조치 로그는 Firehose 역할이 IAM 권한으로 직접 쓰므로 정책 문 불필요.)
# config-baseline 의 3-statement 서비스 principal 패턴을 참조·재사용했다.
data "aws_iam_policy_document" "lake" {
  # --- CloudTrail ---
  statement {
    sid     = "CloudTrailBucketAclCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = [aws_s3_bucket.lake.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  statement {
    sid     = "CloudTrailBucketDelivery"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["cloudtrail.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.lake.arn}/AWSLogs/${local.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceArn"
      values   = [local.trail_arn]
    }
  }

  # --- VPC Flow Logs ---
  statement {
    sid     = "VpcFlowLogsBucketAclCheck"
    effect  = "Allow"
    actions = ["s3:GetBucketAcl"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    resources = [aws_s3_bucket.lake.arn]
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid     = "VpcFlowLogsBucketDelivery"
    effect  = "Allow"
    actions = ["s3:PutObject"]
    principals {
      type        = "Service"
      identifiers = ["delivery.logs.amazonaws.com"]
    }
    resources = ["${aws_s3_bucket.lake.arn}/vpc-flow/AWSLogs/${local.account_id}/*"]
    condition {
      test     = "StringEquals"
      variable = "s3:x-amz-acl"
      values   = ["bucket-owner-full-control"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [local.account_id]
    }
  }
}

resource "aws_s3_bucket_policy" "lake" {
  bucket = aws_s3_bucket.lake.id
  policy = data.aws_iam_policy_document.lake.json
}

# =====================================================================
# 2. CloudTrail (관리 이벤트만, 단일 리전)
# =====================================================================
resource "aws_cloudtrail" "this" {
  count = var.enable_cloudtrail ? 1 : 0

  name           = "${var.name_prefix}-trail"
  s3_bucket_name = aws_s3_bucket.lake.id

  # 관리 이벤트는 기본 포함(read+write). 데이터 이벤트는 비용 때문에 미포함.
  include_global_service_events = true
  is_multi_region_trail         = false
  enable_logging                = true

  # 트레일 생성 시 버킷에 쓰기 권한(버킷 정책)이 먼저 반영돼야 검증을 통과한다.
  depends_on = [aws_s3_bucket_policy.lake]
}

# =====================================================================
# 3. VPC Flow Logs (기본 VPC → S3)
# =====================================================================
data "aws_vpc" "default" {
  count   = var.enable_vpc_flow_logs ? 1 : 0
  default = true
}

resource "aws_flow_log" "default_vpc" {
  count = var.enable_vpc_flow_logs ? 1 : 0

  vpc_id               = data.aws_vpc.default[0].id
  traffic_type         = "ALL"
  log_destination_type = "s3"
  log_destination      = "${aws_s3_bucket.lake.arn}/vpc-flow"

  # ⚠️ EC2 는 flow log 생성 시, 버킷에 필요한 권한이 없으면 버킷 정책을 자동으로
  # "덮어써" delivery.logs 권한만 남길 수 있다(기존 CloudTrail 문 유실 위험).
  # 이 모듈은 aws_s3_bucket_policy.lake 에 delivery.logs 문을 이미 포함하므로 EC2 가
  # 정책을 덮어쓰지 않는다(라이브 배포에서 flow log 활성화 상태로 CloudTrail 정상 전달 확인).
  # 향후 이 전제가 깨지면 flow log 전용 버킷으로 분리한다.
  depends_on = [aws_s3_bucket_policy.lake]
}

# =====================================================================
# 4. Firehose 봉투 제거 변환 Lambda
#    CloudWatch Logs → Firehose 데이터는 gzip + logEvents 봉투로 온다.
#    이 Lambda 가 봉투를 벗겨 원본 조치 JSON 한 줄만 S3 로 흘려보낸다.
# =====================================================================
data "archive_file" "processor" {
  type        = "zip"
  source_file = "${var.processor_lambda_source_dir}/handler.py"
  output_path = "${path.module}/build/log-lake-processor.zip"
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

resource "aws_iam_role" "processor" {
  name               = "${var.name_prefix}-log-lake-processor-role"
  assume_role_policy = data.aws_iam_policy_document.lambda_assume.json
}

resource "aws_cloudwatch_log_group" "processor" {
  name              = "/aws/lambda/${var.name_prefix}-log-lake-processor"
  retention_in_days = 14
}

# 최소 권한: 이 변환 Lambda 는 자기 로그만 쓴다(외부 리소스 접근 없음).
data "aws_iam_policy_document" "processor" {
  statement {
    sid    = "WriteLogs"
    effect = "Allow"
    actions = [
      "logs:CreateLogStream",
      "logs:PutLogEvents",
    ]
    resources = ["${aws_cloudwatch_log_group.processor.arn}:*"]
  }
}

resource "aws_iam_role_policy" "processor" {
  name   = "log-lake-processor"
  role   = aws_iam_role.processor.id
  policy = data.aws_iam_policy_document.processor.json
}

resource "aws_lambda_function" "processor" {
  function_name    = "${var.name_prefix}-log-lake-processor"
  role             = aws_iam_role.processor.arn
  runtime          = "python3.12"
  handler          = "handler.lambda_handler"
  filename         = data.archive_file.processor.output_path
  source_code_hash = data.archive_file.processor.output_base64sha256
  # Firehose 동기 호출: 버퍼 배치 처리에 넉넉히.
  timeout = 60

  depends_on = [
    aws_iam_role_policy.processor,
    aws_cloudwatch_log_group.processor,
  ]
}

# =====================================================================
# 5. Kinesis Firehose (조치 로그 → S3 remediation/ 프리픽스)
# =====================================================================
resource "aws_cloudwatch_log_group" "firehose" {
  name              = "/aws/kinesisfirehose/${var.name_prefix}-remediation-logs"
  retention_in_days = 14
}

resource "aws_cloudwatch_log_stream" "firehose" {
  name           = "S3Delivery"
  log_group_name = aws_cloudwatch_log_group.firehose.name
}

# Firehose 서비스 역할: 레이크 버킷 쓰기 + 변환 Lambda 호출 + 자기 오류 로그.
data "aws_iam_policy_document" "firehose_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["firehose.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "firehose" {
  name               = "${var.name_prefix}-log-lake-firehose-role"
  assume_role_policy = data.aws_iam_policy_document.firehose_assume.json
}

data "aws_iam_policy_document" "firehose" {
  # 버킷 레벨 액션은 버킷 ARN 에만.
  statement {
    sid    = "ListLakeBucket"
    effect = "Allow"
    actions = [
      "s3:GetBucketLocation",
      "s3:ListBucket",
      "s3:ListBucketMultipartUploads",
    ]
    resources = [aws_s3_bucket.lake.arn]
  }

  # 객체 쓰기는 Firehose 가 실제로 쓰는 프리픽스(remediation/, remediation-errors/)로
  # 한정한다. CloudTrail(AWSLogs/)·VPC flow(vpc-flow/) 객체엔 접근 불가(최소 권한).
  statement {
    sid    = "WriteRemediationObjects"
    effect = "Allow"
    actions = [
      "s3:AbortMultipartUpload",
      "s3:GetObject",
      "s3:PutObject",
    ]
    resources = [
      "${aws_s3_bucket.lake.arn}/remediation/*",
      "${aws_s3_bucket.lake.arn}/remediation-errors/*",
    ]
  }

  statement {
    sid    = "InvokeProcessorLambda"
    effect = "Allow"
    actions = [
      "lambda:InvokeFunction",
      "lambda:GetFunctionConfiguration",
    ]
    resources = ["${aws_lambda_function.processor.arn}:*", aws_lambda_function.processor.arn]
  }

  statement {
    sid       = "WriteFirehoseErrorLogs"
    effect    = "Allow"
    actions   = ["logs:PutLogEvents"]
    resources = ["${aws_cloudwatch_log_group.firehose.arn}:*"]
  }
}

resource "aws_iam_role_policy" "firehose" {
  name   = "log-lake-firehose"
  role   = aws_iam_role.firehose.id
  policy = data.aws_iam_policy_document.firehose.json
}

resource "aws_kinesis_firehose_delivery_stream" "remediation" {
  name        = "${var.name_prefix}-remediation-logs"
  destination = "extended_s3"

  extended_s3_configuration {
    role_arn            = aws_iam_role.firehose.arn
    bucket_arn          = aws_s3_bucket.lake.arn
    prefix              = "remediation/"
    error_output_prefix = "remediation-errors/"
    buffering_size      = 5
    buffering_interval  = 60
    # 변환 Lambda 출력(원본 JSON 한 줄)을 S3 에 gzip 으로 저장. Athena 가 gzip JSON 을
    # 그대로 읽는다.
    compression_format = "GZIP"

    cloudwatch_logging_options {
      enabled         = true
      log_group_name  = aws_cloudwatch_log_group.firehose.name
      log_stream_name = aws_cloudwatch_log_stream.firehose.name
    }

    processing_configuration {
      enabled = true
      processors {
        type = "Lambda"
        parameters {
          parameter_name  = "LambdaArn"
          parameter_value = aws_lambda_function.processor.arn
        }
      }
    }
  }
}

# =====================================================================
# 6. CloudWatch Logs → Firehose 구독 필터 (조치 로그 그룹 5개)
# =====================================================================
# CloudWatch Logs 가 Firehose 에 넣을 때 assume 하는 역할.
data "aws_iam_policy_document" "cwl_to_firehose_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["logs.amazonaws.com"]
    }
    # confused deputy 방지: 이 계정의 로그 그룹에서 온 호출만 허용.
    condition {
      test     = "StringLike"
      variable = "aws:SourceArn"
      values   = ["arn:aws:logs:${local.region}:${local.account_id}:*"]
    }
  }
}

resource "aws_iam_role" "cwl_to_firehose" {
  name               = "${var.name_prefix}-cwl-to-firehose-role"
  assume_role_policy = data.aws_iam_policy_document.cwl_to_firehose_assume.json
}

data "aws_iam_policy_document" "cwl_to_firehose" {
  statement {
    sid    = "PutToFirehose"
    effect = "Allow"
    actions = [
      "firehose:PutRecord",
      "firehose:PutRecordBatch",
    ]
    resources = [aws_kinesis_firehose_delivery_stream.remediation.arn]
  }
}

resource "aws_iam_role_policy" "cwl_to_firehose" {
  name   = "cwl-to-firehose"
  role   = aws_iam_role.cwl_to_firehose.id
  policy = data.aws_iam_policy_document.cwl_to_firehose.json
}

# 조치 Lambda 로그 그룹마다 구독 필터 1개. 로그 그룹은 다른 모듈이 만들며,
# 이름이 결정적이라 루트가 목록을 전달한다. (루트에서 depends_on 으로 선존재 보장.)
resource "aws_cloudwatch_log_subscription_filter" "remediation" {
  for_each = toset(var.remediation_log_group_names)

  name           = "${var.name_prefix}-to-log-lake"
  log_group_name = each.value
  # 조치 JSON 로그(event_type=remediation)만 전달한다. 이렇게 하면 Lambda 런타임
  # 플랫폼 로그(INIT_START/START/END/REPORT)가 걸러져 레이크에 순수 조치 JSON 만 쌓인다.
  filter_pattern  = "{ $.event_type = \"remediation\" }"
  destination_arn = aws_kinesis_firehose_delivery_stream.remediation.arn
  role_arn        = aws_iam_role.cwl_to_firehose.arn
}

# =====================================================================
# 7. Glue Data Catalog (external 테이블 3개, 크롤러 없이 프리픽스 스캔)
# =====================================================================
resource "aws_glue_catalog_database" "lake" {
  name = local.glue_db_name
}

# --- 조치 로그: 이미 정규화된 JSON 한 줄 → OpenX JSON SerDe ---
# 선언한 스칼라 컬럼만 읽고, 미선언 필드(applied 등 가변 객체)는 무시한다.
resource "aws_glue_catalog_table" "remediation" {
  database_name = aws_glue_catalog_database.lake.name
  name          = "remediation_logs"
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    classification = "json"
    EXTERNAL       = "TRUE"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.lake.bucket}/remediation/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.openx.data.jsonserde.JsonSerDe"
      parameters = {
        "ignore.malformed.json" = "true"
      }
    }

    columns {
      name = "event_type"
      type = "string"
    }
    columns {
      name = "control"
      type = "string"
    }
    columns {
      name = "status"
      type = "string"
    }
    columns {
      name = "timestamp"
      type = "string"
    }
    columns {
      name = "bucket"
      type = "string"
    }
    columns {
      name = "compliance_before"
      type = "string"
    }
    columns {
      name = "error"
      type = "string"
    }
    columns {
      name = "error_type"
      type = "string"
    }
    columns {
      name = "reason"
      type = "string"
    }
  }
}

# --- CloudTrail: 표준 CloudTrail SerDe + 문서화된 컬럼 세트 ---
resource "aws_glue_catalog_table" "cloudtrail" {
  database_name = aws_glue_catalog_database.lake.name
  name          = "cloudtrail_logs"
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    classification = "cloudtrail"
    EXTERNAL       = "TRUE"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.lake.bucket}/AWSLogs/${local.account_id}/CloudTrail/"
    input_format  = "com.amazon.emr.cloudtrail.CloudTrailInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "com.amazon.emr.hive.serde.CloudTrailSerde"
    }

    columns {
      name = "eventversion"
      type = "string"
    }
    columns {
      name = "useridentity"
      type = "struct<type:string,principalid:string,arn:string,accountid:string,invokedby:string,accesskeyid:string,username:string,sessioncontext:struct<attributes:struct<mfaauthenticated:string,creationdate:string>,sessionissuer:struct<type:string,principalid:string,arn:string,accountid:string,username:string>>>"
    }
    columns {
      name = "eventtime"
      type = "string"
    }
    columns {
      name = "eventsource"
      type = "string"
    }
    columns {
      name = "eventname"
      type = "string"
    }
    columns {
      name = "awsregion"
      type = "string"
    }
    columns {
      name = "sourceipaddress"
      type = "string"
    }
    columns {
      name = "useragent"
      type = "string"
    }
    columns {
      name = "errorcode"
      type = "string"
    }
    columns {
      name = "errormessage"
      type = "string"
    }
    columns {
      name = "requestparameters"
      type = "string"
    }
    columns {
      name = "responseelements"
      type = "string"
    }
    columns {
      name = "additionaleventdata"
      type = "string"
    }
    columns {
      name = "requestid"
      type = "string"
    }
    columns {
      name = "eventid"
      type = "string"
    }
    columns {
      name = "resources"
      type = "array<struct<arn:string,accountid:string,type:string>>"
    }
    columns {
      name = "eventtype"
      type = "string"
    }
    columns {
      name = "apiversion"
      type = "string"
    }
    columns {
      name = "readonly"
      type = "string"
    }
    columns {
      name = "recipientaccountid"
      type = "string"
    }
    columns {
      name = "serviceeventdetails"
      type = "string"
    }
    columns {
      name = "sharedeventid"
      type = "string"
    }
    columns {
      name = "vpcendpointid"
      type = "string"
    }
  }
}

# --- VPC Flow Logs: v2 기본 필드, 공백 구분 텍스트, 헤더 1줄 스킵 ---
resource "aws_glue_catalog_table" "vpc_flow" {
  database_name = aws_glue_catalog_database.lake.name
  name          = "vpc_flow_logs"
  table_type    = "EXTERNAL_TABLE"

  parameters = {
    classification           = "csv"
    EXTERNAL                 = "TRUE"
    "skip.header.line.count" = "1"
  }

  storage_descriptor {
    location      = "s3://${aws_s3_bucket.lake.bucket}/vpc-flow/"
    input_format  = "org.apache.hadoop.mapred.TextInputFormat"
    output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

    ser_de_info {
      serialization_library = "org.apache.hadoop.hive.serde2.lazy.LazySimpleSerDe"
      parameters = {
        "field.delim" = " "
      }
    }

    columns {
      name = "version"
      type = "int"
    }
    columns {
      name = "account_id"
      type = "string"
    }
    columns {
      name = "interface_id"
      type = "string"
    }
    columns {
      name = "srcaddr"
      type = "string"
    }
    columns {
      name = "dstaddr"
      type = "string"
    }
    columns {
      name = "srcport"
      type = "int"
    }
    columns {
      name = "dstport"
      type = "int"
    }
    columns {
      name = "protocol"
      type = "bigint"
    }
    columns {
      name = "packets"
      type = "bigint"
    }
    columns {
      name = "bytes"
      type = "bigint"
    }
    columns {
      name = "start"
      type = "bigint"
    }
    columns {
      name = "end"
      type = "bigint"
    }
    columns {
      name = "action"
      type = "string"
    }
    columns {
      name = "log_status"
      type = "string"
    }
  }
}

# =====================================================================
# 8. Athena (workgroup + 조치 이력 분석 예시 쿼리)
# =====================================================================
resource "aws_athena_workgroup" "lake" {
  name = "${var.name_prefix}-log-lake"
  # 테스트: 쿼리 이력이 있어도 destroy 가능하게.
  force_destroy = true

  configuration {
    enforce_workgroup_configuration    = true
    publish_cloudwatch_metrics_enabled = false

    result_configuration {
      output_location = "s3://${aws_s3_bucket.lake.bucket}/athena-results/"
    }
  }
}

resource "aws_athena_named_query" "recent_remediations" {
  name        = "01-recent-remediations-by-control"
  description = "최근 조치 이력을 control·status 별로 집계"
  database    = aws_glue_catalog_database.lake.name
  workgroup   = aws_athena_workgroup.lake.id
  query       = <<-SQL
    SELECT control, status, count(*) AS events, max(timestamp) AS last_seen
    FROM remediation_logs
    GROUP BY control, status
    ORDER BY control, status;
  SQL
}

resource "aws_athena_named_query" "failed_remediations" {
  name        = "02-failed-remediations"
  description = "실패한 조치(status=error)만 추출"
  database    = aws_glue_catalog_database.lake.name
  workgroup   = aws_athena_workgroup.lake.id
  query       = <<-SQL
    SELECT timestamp, control, bucket, error_type, error
    FROM remediation_logs
    WHERE status = 'error'
    ORDER BY timestamp DESC;
  SQL
}

resource "aws_athena_named_query" "remediation_api_calls" {
  name        = "03-remediation-lambda-api-calls"
  description = "CloudTrail 에서 조치 Lambda 역할이 호출한 API 추적(조치 검증)"
  database    = aws_glue_catalog_database.lake.name
  workgroup   = aws_athena_workgroup.lake.id
  # 조치 Lambda 실행 역할 5개(s3-remediation, s3-kms-remediation, ebs-encryption,
  # iam-detect-notify, iam-approve-remediate)를 모두 포함한다. config/firehose/processor
  # 등 인프라 역할은 제외.
  query = <<-SQL
    SELECT eventtime, eventsource, eventname, useridentity.arn AS actor
    FROM cloudtrail_logs
    WHERE useridentity.arn LIKE '%-remediation-role%'
       OR useridentity.arn LIKE '%-encryption-role%'
       OR useridentity.arn LIKE '%-iam-%-role%'
    ORDER BY eventtime DESC
    LIMIT 100;
  SQL
}

resource "aws_athena_named_query" "who_made_bucket_public" {
  name        = "04-who-changed-s3-public-access"
  description = "누가 S3 퍼블릭 액세스 설정을 바꿨나(조치 이벤트와 상관)"
  database    = aws_glue_catalog_database.lake.name
  workgroup   = aws_athena_workgroup.lake.id
  query       = <<-SQL
    SELECT eventtime, eventname, useridentity.arn AS actor, sourceipaddress
    FROM cloudtrail_logs
    WHERE eventsource = 's3.amazonaws.com'
      AND eventname IN ('PutBucketPublicAccessBlock', 'DeletePublicAccessBlock', 'PutBucketPolicy')
    ORDER BY eventtime DESC
    LIMIT 100;
  SQL
}
