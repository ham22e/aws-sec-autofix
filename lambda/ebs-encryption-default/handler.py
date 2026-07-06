"""EBS 계정 기본 암호화 자동 조치 함수.

AWS Config 규칙 EC2_EBS_ENCRYPTION_BY_DEFAULT 가 NON_COMPLIANT 로 바뀌면
EventBridge 가 이 함수를 호출한다. 함수는 이 리전의 "EBS 기본 암호화"
계정 설정을 켠다.

원칙:
- 멱등적: 이미 기본 암호화가 켜져 있으면 아무것도 바꾸지 않는다.
- 비파괴적: 이 설정은 "신규" 볼륨/스냅샷 복사에만 적용된다. 기존 볼륨은
  전혀 건드리지 않는다(암호화 상태 불변).
- 관측 가능: 조치 결과를 JSON 한 줄 구조화 로그로 남긴다.

⚠️ 이 함수는 "예방"만 자동화한다. 기존 미암호화 볼륨을 실제로 암호화하려면
   스냅샷 → 암호화 복사 → 볼륨 재생성 → detach/attach 가 필요하며, 이는 파괴적
   (다운타임 유발)이라 자동 조치하지 않는다. 기존 볼륨 교정은 런북 참고
   (docs/runbooks/ebs-encryption-default.md).
"""

import datetime
import json

import boto3

ec2 = boto3.client("ec2")

CONTROL = "ebs-encryption-default"


def _log(**fields):
    """조치 이력을 JSON 한 줄로 표준출력에 남긴다(→ CloudWatch Logs)."""
    record = {"event_type": "remediation", "control": CONTROL}
    record.update(fields)
    print(json.dumps(record, ensure_ascii=False, sort_keys=True))


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def lambda_handler(event, context):
    ts = _now()
    # 이 규칙은 계정+리전 단위 설정을 평가하므로, 이벤트 내용과 무관하게
    # 현재 리전의 기본 암호화 설정을 대상으로 동작한다.
    try:
        enabled = ec2.get_ebs_encryption_by_default()["EbsEncryptionByDefault"]

        # 멱등성: 이미 켜져 있으면 건너뛴다.
        if enabled:
            _log(status="already_compliant", timestamp=ts)
            return {"status": "already_compliant"}

        # 비파괴 조치: 계정 기본 암호화를 켠다(신규 볼륨만 영향).
        result = ec2.enable_ebs_encryption_by_default()
        _log(
            status="applied",
            ebs_encryption_by_default=result.get("EbsEncryptionByDefault"),
            timestamp=ts,
        )
        return {"status": "applied"}

    except Exception as exc:  # noqa: BLE001 — 조치 실패도 구조화 로그로 남긴다.
        _log(
            status="error",
            error_type=type(exc).__name__,
            error=str(exc),
            timestamp=ts,
        )
        raise
