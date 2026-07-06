"""IAM 과도 권한 승인 기반 조치 함수 (자동 트리거 없음 — 사람이 수동 invoke).

이 함수는 EventBridge 에 연결돼 있지 않다. 운영자가 알림을 검토한 뒤
`{"policy_arn": "...", "confirm": true}` payload 로 **직접 invoke** 해야만 조치한다.
이것이 "탐지·알림 우선, 조치는 승인 기반" 설계의 승인 게이트다.

조치 방식(라이트사이징):
- 대상 고객관리형 정책의 **기본 버전을 최소 권한 문서로 교체**한다
  (CreatePolicyVersion + SetAsDefault). 규칙은 정책의 '기본 버전'을 평가하므로,
  이렇게 해야 COMPLIANT 로 전환된다. (부착만 detach 하면 규칙은 그대로 NON_COMPLIANT.)
- **비파괴·가역**: 정책/역할을 삭제하지 않는다. 기존 버전은 보존되므로
  SetDefaultPolicyVersion 으로 언제든 되돌릴 수 있다(런북 참고).
- IAM 은 정책당 버전 5개 제한 → 가득 차면 가장 오래된 비-기본 버전 1개를 지운다.

원칙:
- 승인 게이트: confirm != true 면 아무것도 바꾸지 않는다.
- 멱등: 기본 버전에 admin 문이 없으면 already_remediated 로 종료.
- 관측 가능: 결과를 JSON 한 줄 구조화 로그로 남긴다.
"""

import datetime
import json
import os
import urllib.parse

import boto3

iam = boto3.client("iam")

DEFAULT_POLICY_ARN = os.environ.get("DEFAULT_POLICY_ARN", "")

CONTROL = "iam-excessive-privilege"

# payload 에 replacement_document 가 없을 때 적용할 문서화된 최소 권한 기본값.
# 실무에서는 운영자가 실제 필요한 권한만 담은 정책을 넘긴다(이건 안전한 자리표시자).
MINIMAL_DOC = {
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "MinimalLeastPrivilege",
            "Effect": "Allow",
            "Action": "sts:GetCallerIdentity",
            "Resource": "*",
        }
    ],
}


def _log(**fields):
    record = {"event_type": "remediation", "control": CONTROL}
    record.update(fields)
    print(json.dumps(record, ensure_ascii=False, sort_keys=True))


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def _decode_document(raw):
    """IAM GetPolicyVersion 의 Document(URL 인코딩 JSON 문자열)를 dict 로 디코드."""
    if isinstance(raw, dict):
        return raw
    return json.loads(urllib.parse.unquote(raw))


def _statements(doc):
    stmts = doc.get("Statement", [])
    return [stmts] if isinstance(stmts, dict) else stmts


def _has_admin(doc):
    """기본 버전에 Effect:Allow + Action:* + Resource:* 문이 있는지."""
    for s in _statements(doc):
        if s.get("Effect") != "Allow":
            continue
        actions = s.get("Action", [])
        resources = s.get("Resource", [])
        if isinstance(actions, str):
            actions = [actions]
        if isinstance(resources, str):
            resources = [resources]
        if "*" in actions and "*" in resources:
            return True
    return False


def _make_room(policy_arn):
    """버전이 5개(상한)면 가장 오래된 비-기본 버전 1개를 삭제해 자리를 만든다."""
    versions = iam.list_policy_versions(PolicyArn=policy_arn)["Versions"]
    if len(versions) < 5:
        return None
    non_default = [v for v in versions if not v["IsDefaultVersion"]]
    oldest = min(non_default, key=lambda v: int(v["VersionId"].lstrip("v")))
    iam.delete_policy_version(PolicyArn=policy_arn, VersionId=oldest["VersionId"])
    return oldest["VersionId"]


def lambda_handler(event, context):
    ts = _now()
    event = event or {}
    policy_arn = event.get("policy_arn") or DEFAULT_POLICY_ARN
    confirm = event.get("confirm", False)
    replacement = event.get("replacement_document") or MINIMAL_DOC

    # 승인 게이트: 명시적 confirm:true 없이는 어떤 것도 바꾸지 않는다.
    if confirm is not True:
        _log(status="rejected_no_confirmation", policy_arn=policy_arn, timestamp=ts)
        return {"status": "rejected_no_confirmation"}

    if not policy_arn:
        _log(status="skipped", reason="no_policy_arn", timestamp=ts)
        return {"status": "skipped"}

    # 교체 문서 자체가 admin 이면 조치해도 COMPLIANT 가 안 되므로 거부한다.
    if _has_admin(replacement):
        _log(status="rejected_replacement_has_admin", policy_arn=policy_arn, timestamp=ts)
        return {"status": "rejected_replacement_has_admin"}

    try:
        default_version = iam.get_policy(PolicyArn=policy_arn)["Policy"]["DefaultVersionId"]
        raw = iam.get_policy_version(PolicyArn=policy_arn, VersionId=default_version)[
            "PolicyVersion"
        ]["Document"]
        current_doc = _decode_document(raw)

        # 멱등: 이미 admin 이 아니면 아무것도 하지 않는다.
        if not _has_admin(current_doc):
            _log(
                status="already_remediated",
                policy_arn=policy_arn,
                default_version=default_version,
                timestamp=ts,
            )
            return {"status": "already_remediated", "policy_arn": policy_arn}

        deleted_version = _make_room(policy_arn)
        new_version = iam.create_policy_version(
            PolicyArn=policy_arn,
            PolicyDocument=json.dumps(replacement),
            SetAsDefault=True,
        )["PolicyVersion"]["VersionId"]

        _log(
            status="applied",
            policy_arn=policy_arn,
            previous_default_version=default_version,
            new_default_version=new_version,
            deleted_version=deleted_version,
            replacement_statement_count=len(_statements(replacement)),
            timestamp=ts,
        )
        return {
            "status": "applied",
            "policy_arn": policy_arn,
            "new_default_version": new_version,
        }

    except Exception as exc:  # noqa: BLE001 — 실패도 구조화 로그로 남긴다.
        _log(
            status="error",
            policy_arn=policy_arn,
            error_type=type(exc).__name__,
            error=str(exc),
            timestamp=ts,
        )
        raise
