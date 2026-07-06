"""IAM 과도 권한 탐지·알림 함수 (자동 트리거, 정책 무변경).

AWS Config 규칙 IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS 가 NON_COMPLIANT 로
바뀌면 EventBridge 가 이 함수를 호출한다. 함수는 알림만 보내고 **정책을 변경하지
않는다.** 실제 권한 변경은 사람이 승인 조치 Lambda 를 수동 invoke 할 때만 일어난다.

왜 자동 조치하지 않는가: IAM 권한을 자동 회수하면 정당한 워크로드·운영자 접근이
즉시 끊겨 서비스 중단(사실상 self-inflicted DoS)이 될 수 있다. 그래서 IAM 은
"탐지·알림 우선, 조치는 승인 기반"으로 설계한다.
(근거: docs/runbooks/iam-excessive-privilege.md)

원칙:
- 비파괴: 어떤 정책·역할도 변경/삭제하지 않는다. 알림만 발행한다.
- 관측 가능: 결과를 JSON 한 줄 구조화 로그로 남긴다.
"""

import datetime
import json
import os

import boto3
from botocore.exceptions import ClientError

iam = boto3.client("iam")
sns = boto3.client("sns")

SNS_TOPIC_ARN = os.environ.get("SNS_TOPIC_ARN")
APPROVE_FUNCTION_NAME = os.environ.get("APPROVE_FUNCTION_NAME", "")
VULNERABLE_POLICY_ARN = os.environ.get("VULNERABLE_POLICY_ARN", "")

CONTROL = "iam-excessive-privilege"


def _log(**fields):
    """조치 이력을 JSON 한 줄로 표준출력에 남긴다(→ CloudWatch Logs)."""
    record = {"event_type": "remediation", "control": CONTROL}
    record.update(fields)
    print(json.dumps(record, ensure_ascii=False, sort_keys=True))


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _attached_entities(policy_arn):
    """테스트 대상 정책에 부착된 주체(역할·사용자·그룹) 이름 목록을 반환한다.

    Config 이벤트는 정책 ID 만 주므로, 배포 시점에 아는 테스트 정책 ARN 으로 조회한다.
    조회 실패(권한/삭제 등)는 알림을 막지 않고 None 으로 축약한다.
    """
    if not policy_arn:
        return None
    try:
        resp = iam.list_entities_for_policy(PolicyArn=policy_arn)
        return {
            "roles": [r["RoleName"] for r in resp.get("PolicyRoles", [])],
            "users": [u["UserName"] for u in resp.get("PolicyUsers", [])],
            "groups": [g["GroupName"] for g in resp.get("PolicyGroups", [])],
        }
    except ClientError:
        return None


def _build_message(policy_id, compliance, account, region, entities):
    """사람이 읽을 알림 본문. 무엇이/어디에/어떻게 조치하는지 안내한다."""
    lines = [
        "[AutoFix] IAM 과도 권한 탐지 (관리자 권한 정책)",
        "",
        f"- 규칙: IAM_POLICY_NO_STATEMENTS_WITH_ADMIN_ACCESS = {compliance}",
        f"- 대상 정책 ID: {policy_id}",
        f"- 계정/리전: {account} / {region}",
        f"- 테스트 대상 정책 ARN: {VULNERABLE_POLICY_ARN or '(미설정)'}",
    ]
    if entities is not None:
        lines.append(
            "- 부착 주체(영향 범위): "
            f"roles={entities['roles']} users={entities['users']} groups={entities['groups']}"
        )
    lines += [
        "",
        "이 결함은 자동 조치되지 않습니다(권한 자동 회수는 서비스 중단 위험).",
        "검토 후 승인하려면 아래 조치 함수를 수동 invoke 하세요:",
        f"  aws lambda invoke --function-name {APPROVE_FUNCTION_NAME} \\",
        f"    --payload '{{\"policy_arn\":\"{VULNERABLE_POLICY_ARN}\",\"confirm\":true}}' out.json",
        "",
        "자세한 절차: docs/runbooks/iam-excessive-privilege.md",
    ]
    return "\n".join(lines)


def lambda_handler(event, context):
    ts = _now()
    detail = (event or {}).get("detail", {})
    policy_id = detail.get("resourceId")
    compliance = detail.get("newEvaluationResult", {}).get("complianceType")
    account = detail.get("awsAccountId")
    region = detail.get("awsRegion")

    # 이벤트에서 대상을 특정할 수 없으면 알림 없이 기록만 한다.
    if not policy_id:
        _log(status="skipped", reason="no_resource_in_event", timestamp=ts)
        return {"status": "skipped"}

    try:
        entities = _attached_entities(VULNERABLE_POLICY_ARN)
        message = _build_message(policy_id, compliance, account, region, entities)

        sns.publish(
            TopicArn=SNS_TOPIC_ARN,
            Subject="[AutoFix] IAM 과도 권한 탐지 — 승인 조치 필요",
            Message=message,
        )

        _log(
            status="notified",
            policy_id=policy_id,
            compliance=compliance,
            attached_entities=entities,
            topic=SNS_TOPIC_ARN,
            timestamp=ts,
        )
        return {"status": "notified", "policy_id": policy_id}

    except Exception as exc:  # noqa: BLE001 — 실패도 구조화 로그로 남긴다.
        _log(
            status="error",
            policy_id=policy_id,
            error_type=type(exc).__name__,
            error=str(exc),
            timestamp=ts,
        )
        raise
