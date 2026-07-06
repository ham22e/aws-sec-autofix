"""S3 퍼블릭 노출 자동 조치 함수.

AWS Config 규칙 S3_BUCKET_PUBLIC_READ_PROHIBITED 이 NON_COMPLIANT 로 바뀌면
EventBridge 가 이 함수를 호출한다. 함수는 대상 버킷의 Block Public Access(BPA)
4종을 모두 켜서 노출만 차단한다.

원칙:
- 멱등적: 이미 4종이 켜져 있으면 아무것도 바꾸지 않는다.
- 비파괴적: BPA 만 켠다. 버킷/객체/버킷 정책은 삭제하지 않는다(노출만 차단).
- 관측 가능: 조치 결과를 JSON 한 줄 구조화 로그로 남긴다.
"""

import datetime
import json

import boto3
from botocore.exceptions import ClientError

s3 = boto3.client("s3")

# Block Public Access 4종을 모두 켠 목표 상태.
BLOCK_ALL = {
    "BlockPublicAcls": True,
    "IgnorePublicAcls": True,
    "BlockPublicPolicy": True,
    "RestrictPublicBuckets": True,
}


def _log(**fields):
    """조치 이력을 JSON 한 줄로 표준출력에 남긴다(→ CloudWatch Logs)."""
    record = {"event_type": "remediation", "control": "s3-public-access"}
    record.update(fields)
    print(json.dumps(record, ensure_ascii=False, sort_keys=True))


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def lambda_handler(event, context):
    ts = _now()
    detail = (event or {}).get("detail", {})
    bucket = detail.get("resourceId")
    compliance_before = detail.get("newEvaluationResult", {}).get("complianceType")

    # 이벤트에서 버킷을 특정할 수 없으면 조치하지 않고 기록만 한다.
    if not bucket:
        _log(status="skipped", reason="no_bucket_in_event", timestamp=ts)
        return {"status": "skipped"}

    try:
        # 멱등성: 현재 BPA 상태를 먼저 확인해 이미 안전하면 건너뛴다.
        try:
            current = s3.get_public_access_block(Bucket=bucket)[
                "PublicAccessBlockConfiguration"
            ]
        except ClientError as err:
            # BPA 설정이 아예 없는 버킷은 이 코드로 응답한다 → 미설정으로 간주.
            if err.response["Error"]["Code"] == "NoSuchPublicAccessBlockConfiguration":
                current = {}
            else:
                raise

        if current == BLOCK_ALL:
            _log(
                status="already_compliant",
                bucket=bucket,
                compliance_before=compliance_before,
                timestamp=ts,
            )
            return {"status": "already_compliant", "bucket": bucket}

        # 비파괴 조치: BPA 4종만 켠다.
        s3.put_public_access_block(
            Bucket=bucket, PublicAccessBlockConfiguration=BLOCK_ALL
        )
        _log(
            status="applied",
            bucket=bucket,
            compliance_before=compliance_before,
            applied=BLOCK_ALL,
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
