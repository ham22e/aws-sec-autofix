"""S3 KMS 기본 암호화 자동 조치 함수.

AWS Config 규칙 S3_DEFAULT_ENCRYPTION_KMS 가 NON_COMPLIANT 로 바뀌면
EventBridge 가 이 함수를 호출한다. 함수는 대상 버킷의 기본 암호화를
고객관리형 KMS 키(SSE-KMS)로 설정한다.

원칙:
- 멱등적: 이미 대상 KMS 키로 SSE-KMS 가 설정돼 있으면 아무것도 바꾸지 않는다.
- 비파괴적: 버킷 기본 암호화 설정만 바꾼다. 버킷/객체는 삭제하지 않는다.
  기존 객체는 재암호화되지 않고 그대로 남으며, 신규 객체부터 KMS 로 암호화된다.
- 관측 가능: 조치 결과를 JSON 한 줄 구조화 로그로 남긴다.

조치 자체가 "버킷 암호화 구성 변경"이라, Config 가 이를 감지해 규칙을
자동 재평가하고 COMPLIANT 로 전환한다(강제 평가 불필요).
"""

import datetime
import json
import os

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")

# 조치가 적용할 대상 KMS 키 ARN. Terraform 이 배포 시점에 주입한다.
KMS_KEY_ARN = os.environ.get("KMS_KEY_ARN", "")
# 이벤트에서 버킷을 특정하지 못할 때 사용할 대상 버킷(테스트 버킷).
TARGET_BUCKET = os.environ.get("TARGET_BUCKET", "")

CONTROL = "s3-kms-encryption"


def _log(**fields):
    """조치 이력을 JSON 한 줄로 표준출력에 남긴다(→ CloudWatch Logs)."""
    record = {"event_type": "remediation", "control": CONTROL}
    record.update(fields)
    print(json.dumps(record, ensure_ascii=False, sort_keys=True))


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _current_kms_key(bucket):
    """버킷 기본 암호화가 SSE-KMS 이면 그 키 ID 를, 아니면 None 을 반환한다."""
    try:
        rules = s3.get_bucket_encryption(Bucket=bucket)[
            "ServerSideEncryptionConfiguration"
        ]["Rules"]
    except ClientError as err:
        # 기본 암호화가 아예 없는 버킷은 이 코드로 응답한다 → 미설정으로 간주.
        if err.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            return None
        raise

    for rule in rules:
        sse = rule.get("ApplyServerSideEncryptionByDefault", {})
        if sse.get("SSEAlgorithm") == "aws:kms":
            return sse.get("KMSMasterKeyID")
    return None


def lambda_handler(event, context):
    ts = _now()
    detail = (event or {}).get("detail", {})
    bucket = detail.get("resourceId") or TARGET_BUCKET

    # 이벤트로도 환경변수로도 버킷을 특정할 수 없으면 조치하지 않고 기록만 한다.
    if not bucket:
        _log(status="skipped", reason="no_bucket_in_event", timestamp=ts)
        return {"status": "skipped"}

    try:
        # 멱등성: 이미 대상 KMS 키로 암호화돼 있으면 건너뛴다.
        current_key = _current_kms_key(bucket)
        if current_key == KMS_KEY_ARN:
            _log(
                status="already_compliant",
                bucket=bucket,
                kms_key=current_key,
                timestamp=ts,
            )
            return {"status": "already_compliant", "bucket": bucket}

        # 비파괴 조치: 버킷 기본 암호화를 SSE-KMS 로 설정한다.
        # BucketKeyEnabled=true 로 S3 버킷 키를 켜 KMS 호출·비용을 줄인다.
        s3.put_bucket_encryption(
            Bucket=bucket,
            ServerSideEncryptionConfiguration={
                "Rules": [
                    {
                        "ApplyServerSideEncryptionByDefault": {
                            "SSEAlgorithm": "aws:kms",
                            "KMSMasterKeyID": KMS_KEY_ARN,
                        },
                        "BucketKeyEnabled": True,
                    }
                ]
            },
        )
        _log(
            status="applied",
            bucket=bucket,
            kms_key=KMS_KEY_ARN,
            previous_kms_key=current_key,
            timestamp=ts,
        )
        return {"status": "applied", "bucket": bucket}

    except Exception as exc:  # noqa: BLE001 — 조치 실패도 구조화 로그로 남긴다.
        _log(
            status="error",
            bucket=bucket,
            error_type=type(exc).__name__,
            error=str(exc),
            timestamp=ts,
        )
        raise
