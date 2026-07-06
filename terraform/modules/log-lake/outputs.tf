output "lake_bucket" {
  description = "세 소스 로그가 모이는 S3 로그 레이크 버킷 이름"
  value       = aws_s3_bucket.lake.bucket
}

output "glue_database_name" {
  description = "Athena 조회용 Glue 데이터베이스 이름"
  value       = aws_glue_catalog_database.lake.name
}

output "athena_workgroup" {
  description = "조치 이력 분석용 Athena 작업 그룹 이름"
  value       = aws_athena_workgroup.lake.id
}

output "cloudtrail_name" {
  description = "생성된 CloudTrail 트레일 이름 (enable_cloudtrail=false 면 null)"
  value       = var.enable_cloudtrail ? aws_cloudtrail.this[0].name : null
}

output "firehose_stream_name" {
  description = "조치 로그 수집 Firehose 스트림 이름"
  value       = aws_kinesis_firehose_delivery_stream.remediation.name
}
