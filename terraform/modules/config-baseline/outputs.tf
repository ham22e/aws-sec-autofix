output "recorder_name" {
  description = "생성된 Configuration Recorder 이름"
  value       = aws_config_configuration_recorder.this.name
}

output "config_bucket" {
  description = "Config 스냅샷 전달용 S3 버킷 이름"
  value       = aws_s3_bucket.config.bucket
}
