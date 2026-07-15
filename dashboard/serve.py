#!/usr/bin/env python3
"""탐지·조치 현황 웹 대시보드 (로컬 실행).

CloudWatch 대시보드(terraform/modules/dashboard/)와 병행 운영한다. 같은 사실을
보되 소스가 다르다. CloudWatch 는 metric filter 가 만든 커스텀 메트릭을 읽고,
이 대시보드는 AWS Config 와 CloudWatch Logs 를 직접 읽는다.

직접 읽는 이유: 메트릭은 차원(control·status)만 담을 수 있어서 "지금 어느 버킷이
위반 중인가", "어떤 KMS 키가 적용됐나" 같은 리소스 단위 정보를 잃는다. Config 의
GetComplianceDetailsByConfigRule 과 조치 로그 원본 JSON 을 직접 읽으면 그 정보가 산다.

AWS 리소스를 새로 만들지 않는다. 읽기 전용 API 3종만 호출한다.

실행:
    python serve.py --profile <프로필>   # 라이브 (terraform apply 이후)
    python serve.py --sample             # 샘플 데이터 (AWS 불필요)
"""

import argparse
import datetime
import json
import subprocess
import sys
from collections import Counter
from functools import partial
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

import boto3
from botocore.exceptions import BotoCoreError, ClientError, ProfileNotFound

BASE_DIR = Path(__file__).resolve().parent
STATIC_DIR = BASE_DIR / "static"
SAMPLE_FILE = BASE_DIR / "sample-snapshot.json"

# 조치 Lambda 가 남기는 JSON 한 줄 로그만 고른다. 이 패턴이 Lambda 런타임 플랫폼
# 로그(INIT_START/START/END/REPORT)를 걸러낸다. metric filter·구독 필터와 같은 패턴.
REMEDIATION_FILTER = '{ $.event_type = "remediation" }'

RANGES = {"1h": 3600, "24h": 86400, "7d": 604800}
DEFAULT_RANGE = "24h"

STATIC_FILES = {
    "/": ("index.html", "text/html; charset=utf-8"),
    "/index.html": ("index.html", "text/html; charset=utf-8"),
    "/app.js": ("app.js", "text/javascript; charset=utf-8"),
    "/style.css": ("style.css", "text/css; charset=utf-8"),
}

# 통제 4종. Config 규칙 이름과 Lambda 이름은 여기 두지 않고 terraform output 키로만
# 참조한다(하드코딩 금지: project_name 을 바꿔도 그대로 동작해야 한다).
SCENARIOS = [
    {
        "control": "s3-public-access",
        "title": "S3 퍼블릭 노출",
        "rule_key": "config_rule_name",
        "lambda_keys": ["lambda_function_name"],
        "mode": "auto",
        "runbook": "docs/runbooks/s3-public-access.md",
    },
    {
        "control": "iam-excessive-privilege",
        "title": "IAM 과도 권한 (CIEM)",
        "rule_key": "iam_config_rule_name",
        # 탐지·알림과 승인 조치 두 Lambda 가 같은 control 로 로그를 남긴다 → 로그 그룹 2개.
        "lambda_keys": ["iam_detect_notify_lambda", "iam_approve_remediate_lambda"],
        "mode": "approval",
        "runbook": "docs/runbooks/iam-excessive-privilege.md",
    },
    {
        "control": "s3-kms-encryption",
        "title": "S3 저장 데이터 암호화 (KMS)",
        "rule_key": "s3_kms_config_rule_name",
        "lambda_keys": ["s3_kms_lambda_function_name"],
        "mode": "auto",
        "runbook": "docs/runbooks/s3-kms-encryption.md",
    },
    {
        "control": "ebs-encryption-default",
        "title": "EBS 기본 암호화",
        "rule_key": "ebs_config_rule_name",
        "lambda_keys": ["ebs_lambda_function_name"],
        "mode": "auto",
        "runbook": "docs/runbooks/ebs-encryption-default.md",
    },
]

REQUIRED_KEYS = [m["rule_key"] for m in SCENARIOS] + [
    key for m in SCENARIOS for key in m["lambda_keys"]
]


def _msg(exc):
    """boto3 예외를 사람이 읽을 한 줄로 줄인다."""
    if isinstance(exc, ClientError):
        return exc.response["Error"].get("Message", str(exc))
    return str(exc)


# =====================================================================
# 로그 레코드 → 타임라인 행
# =====================================================================
def _resource(record):
    """조치 대상 리소스 식별자. 시나리오마다 필드명이 다르다."""
    for key in ("bucket", "policy_arn", "policy_id"):
        if record.get(key):
            return record[key]
    # EBS 기본 암호화는 계정 단위 설정이라 대상 리소스가 없다.
    return "-"


def _detail(record):
    """조치 내용 요약. 로그에 실제로 있는 필드만 골라 한 줄로 만든다."""
    if record.get("error_type"):
        return f"{record['error_type']}: {record.get('error', '')}".strip(": ")
    if record.get("reason"):
        return record["reason"]
    if record.get("kms_key"):
        return f"KMS 키 {record['kms_key'].rsplit('/', 1)[-1]}"
    if record.get("ebs_encryption_by_default") is not None:
        return f"계정 기본 암호화 = {record['ebs_encryption_by_default']}"
    if record.get("applied"):
        return "Block Public Access 4종 적용"
    if record.get("new_default_version"):
        prev = record.get("previous_default_version", "?")
        return f"정책 기본 버전 {prev} → {record['new_default_version']}"
    if record.get("topic"):
        return "SNS 알림 발행 (승인 대기)"
    return "-"


def _row(record):
    return {
        "timestamp": record.get("timestamp", ""),
        "control": record.get("control", "-"),
        "status": record.get("status", "unknown"),
        "resource": _resource(record),
        "detail": _detail(record),
    }


# =====================================================================
# 데이터 소스: 라이브(AWS) / 샘플(파일). 조립 코드는 이 인터페이스만 안다.
# =====================================================================
class AwsSource:
    """AWS Config + CloudWatch Logs 를 읽기 전용으로 조회한다."""

    sample = False

    def __init__(self, profile, region, terraform_dir):
        try:
            session = boto3.Session(profile_name=profile, region_name=region)
        except ProfileNotFound as exc:
            raise RuntimeError(f"AWS 프로필을 찾을 수 없다: {exc}")

        # 자격증명을 시작 시점에 검증한다. 안 그러면 첫 요청에서야 터진다.
        try:
            session.client("sts").get_caller_identity()
        except (ClientError, BotoCoreError) as exc:
            raise RuntimeError(
                f"AWS 자격증명 확인 실패: {_msg(exc)}\n"
                "--profile 값이 맞는지, 자격증명이 만료되지 않았는지 확인하라."
            )

        self.outputs = _terraform_outputs(terraform_dir)
        self.region = region
        self._config = session.client("config")
        self._logs = session.client("logs")

    def compliance(self, rule_names):
        resp = self._config.describe_compliance_by_config_rule(ConfigRuleNames=rule_names)
        return {
            item["ConfigRuleName"]: item.get("Compliance", {}).get("ComplianceType")
            for item in resp.get("ComplianceByConfigRules", [])
        }

    def violating(self, rule_name):
        resp = self._config.get_compliance_details_by_config_rule(
            ConfigRuleName=rule_name, ComplianceTypes=["NON_COMPLIANT"]
        )
        return [
            r["EvaluationResultIdentifier"]["EvaluationResultQualifier"]["ResourceId"]
            for r in resp.get("EvaluationResults", [])
        ]

    def records(self, log_group, start_ms):
        try:
            pages = self._logs.get_paginator("filter_log_events").paginate(
                logGroupName=log_group,
                filterPattern=REMEDIATION_FILTER,
                startTime=start_ms,
            )
            events = [e for page in pages for e in page.get("events", [])]
        except ClientError as exc:
            # 배포 직후 Lambda 가 아직 한 번도 안 돌았으면 로그 그룹이 없다. 조치 이력이
            # 없는 것이지 오류가 아니다.
            if exc.response["Error"]["Code"] == "ResourceNotFoundException":
                return []
            raise

        records = []
        for event in events:
            try:
                records.append(json.loads(event["message"]))
            except json.JSONDecodeError:
                continue
        return records


class SampleSource:
    """sample-snapshot.json 을 읽는다. AWS 를 조회하지 않는다.

    라이브와 같은 조립 코드를 타도록 "완성된 응답"이 아니라 "원본 재료"(Config 상태 +
    조치 로그 레코드)를 담는다. 그래서 스키마가 어긋날 수 없다.
    """

    sample = True

    def __init__(self):
        try:
            data = json.loads(SAMPLE_FILE.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RuntimeError(f"샘플 파일을 읽을 수 없다 ({SAMPLE_FILE}): {exc}")

        self.outputs = data["outputs"]
        self.region = data["region"]
        self._compliance = data["compliance"]
        self._violating = data["violating_resources"]
        self._log_events = _rebase_to_now(data["log_events"])

        missing = [k for k in REQUIRED_KEYS if not self.outputs.get(k)]
        if missing:
            raise RuntimeError(
                f"샘플 파일의 outputs 에 필요한 키가 없다: {', '.join(missing)}"
            )

    def compliance(self, rule_names):
        return {name: self._compliance.get(name) for name in rule_names}

    def violating(self, rule_name):
        return self._violating.get(rule_name, [])

    def records(self, log_group, start_ms):
        start = datetime.datetime.fromtimestamp(start_ms / 1000, datetime.timezone.utc)
        return [
            r
            for r in self._log_events.get(log_group, [])
            if datetime.datetime.fromisoformat(r["timestamp"]) >= start
        ]


def _rebase_to_now(log_events):
    """샘플 로그의 타임스탬프를 지금 기준으로 당긴다(상대 간격은 유지).

    샘플 파일에 고정 시각을 박아두면 시간이 흐를수록 전부 조회 범위 밖으로 밀려나
    기간 셀렉터(1h/24h/7d)가 아무것도 못 보여준다. 가장 최근 이벤트가 "3분 전"이
    되도록 전체를 평행이동한다.
    """
    stamps = [
        datetime.datetime.fromisoformat(r["timestamp"])
        for records in log_events.values()
        for r in records
    ]
    if not stamps:
        return log_events

    now = datetime.datetime.now(datetime.timezone.utc)
    shift = (now - datetime.timedelta(minutes=3)) - max(stamps)

    return {
        group: [
            {
                **r,
                "timestamp": (
                    datetime.datetime.fromisoformat(r["timestamp"]) + shift
                ).isoformat(),
            }
            for r in records
        ]
        for group, records in log_events.items()
    }


def _terraform_outputs(terraform_dir):
    """terraform output -json 으로 Config 규칙·Lambda 이름을 가져온다."""
    try:
        proc = subprocess.run(
            ["terraform", "output", "-json"],
            cwd=terraform_dir,
            capture_output=True,
            text=True,
            check=True,
        )
    except FileNotFoundError:
        raise RuntimeError("terraform 실행 파일을 찾을 수 없다. PATH 를 확인하라.")
    except NotADirectoryError:
        raise RuntimeError(f"terraform 디렉터리가 아니다: {terraform_dir}")
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(
            f"terraform output 실패 ({terraform_dir}):\n{exc.stderr.strip()}"
        )

    raw = json.loads(proc.stdout or "{}")
    outputs = {key: value.get("value") for key, value in raw.items()}

    missing = [k for k in REQUIRED_KEYS if not outputs.get(k)]
    if missing:
        raise RuntimeError(
            "terraform output 에 필요한 값이 없다: "
            + ", ".join(missing)
            + "\nterraform apply 가 끝난 상태인지 확인하라. "
            "배포 전이라면 --sample 로 UI 만 볼 수 있다."
        )
    return outputs


# =====================================================================
# 스냅샷 조립 (라이브·샘플 공통)
# =====================================================================
def build_snapshot(source, range_key):
    now = datetime.datetime.now(datetime.timezone.utc)
    start_ms = int((now.timestamp() - RANGES[range_key]) * 1000)

    outputs = source.outputs
    errors = []

    rule_names = [outputs[m["rule_key"]] for m in SCENARIOS]
    try:
        states = source.compliance(rule_names)
    except (ClientError, BotoCoreError) as exc:
        states = {}
        errors.append(f"Config 준수 상태 조회 실패: {_msg(exc)}")

    scenarios = []
    timeline = []

    for meta in SCENARIOS:
        rule = outputs[meta["rule_key"]]
        # INSUFFICIENT_DATA·NOT_APPLICABLE 은 판정 불가 → 평가 대기(None)로 접는다.
        # compliance-metrics Lambda 가 준수율 분모에서 빼는 것과 같은 규칙이다.
        state = states.get(rule)
        if state not in ("COMPLIANT", "NON_COMPLIANT"):
            state = None

        card_error = None
        violating = []
        if state == "NON_COMPLIANT":
            try:
                violating = source.violating(rule)
            except (ClientError, BotoCoreError) as exc:
                card_error = f"위반 리소스 조회 실패: {_msg(exc)}"

        rows = []
        for key in meta["lambda_keys"]:
            log_group = f"/aws/lambda/{outputs[key]}"
            try:
                rows.extend(_row(r) for r in source.records(log_group, start_ms))
            except (ClientError, BotoCoreError) as exc:
                card_error = f"조치 로그 조회 실패: {_msg(exc)}"

        rows.sort(key=lambda r: r["timestamp"], reverse=True)

        if card_error:
            errors.append(f"[{meta['title']}] {card_error}")

        scenarios.append(
            {
                "control": meta["control"],
                "title": meta["title"],
                "config_rule": rule,
                "compliance": state,
                "violating_resources": violating,
                "mode": meta["mode"],
                "runbook": meta["runbook"],
                "event_counts": dict(Counter(r["status"] for r in rows)),
                "last_event": rows[0] if rows else None,
                "error": card_error,
            }
        )
        timeline.extend(rows)

    timeline.sort(key=lambda r: r["timestamp"], reverse=True)

    compliant = sum(1 for s in scenarios if s["compliance"] == "COMPLIANT")
    non_compliant = sum(1 for s in scenarios if s["compliance"] == "NON_COMPLIANT")
    evaluated = compliant + non_compliant

    return {
        "generated_at": now.isoformat(),
        "region": source.region,
        "range": range_key,
        "sample": source.sample,
        "cloudwatch_dashboard_url": outputs.get("dashboard_url"),
        "summary": {
            # 준수율 공식은 lambda/compliance-metrics/handler.py 와 같아야 한다.
            # 두 대시보드가 다른 숫자를 내면 둘 중 하나가 틀린 것이다.
            "compliance_rate": round(100.0 * compliant / evaluated, 1) if evaluated else None,
            "compliant_rules": compliant,
            "non_compliant_rules": non_compliant,
            "pending_rules": len(scenarios) - evaluated,
            "event_counts": dict(Counter(r["status"] for r in timeline)),
        },
        "scenarios": scenarios,
        "timeline": timeline,
        "errors": errors,
    }


# =====================================================================
# HTTP 서버 (127.0.0.1 전용)
# =====================================================================
class DashboardHandler(BaseHTTPRequestHandler):
    def __init__(self, *args, source, **kwargs):
        self.source = source
        super().__init__(*args, **kwargs)

    def do_GET(self):
        parsed = urlparse(self.path)

        if parsed.path == "/api/snapshot":
            query = parse_qs(parsed.query)
            requested = (query.get("range") or [DEFAULT_RANGE])[0]
            range_key = requested if requested in RANGES else DEFAULT_RANGE
            body = json.dumps(
                build_snapshot(self.source, range_key), ensure_ascii=False
            ).encode("utf-8")
            self._respond("application/json; charset=utf-8", body)
            return

        static = STATIC_FILES.get(parsed.path)
        if static is None:
            self.send_error(404)
            return

        filename, content_type = static
        self._respond(content_type, (STATIC_DIR / filename).read_bytes())

    def _respond(self, content_type, body):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        sys.stderr.write(f"  {fmt % args}\n")


def main():
    parser = argparse.ArgumentParser(
        description="탐지·조치 현황 웹 대시보드 (로컬 실행, 읽기 전용)"
    )
    parser.add_argument("--profile", help="AWS CLI 프로필 이름")
    parser.add_argument("--region", default="ap-northeast-2", help="조회할 리전")
    parser.add_argument("--port", type=int, default=8000, help="바인드할 포트")
    parser.add_argument(
        "--terraform-dir",
        default=str(BASE_DIR.parent / "terraform"),
        help="terraform output 을 읽을 디렉터리",
    )
    parser.add_argument(
        "--sample",
        action="store_true",
        help="AWS 대신 sample-snapshot.json 을 쓴다 (배포 전 UI 확인용)",
    )
    args = parser.parse_args()

    try:
        source = (
            SampleSource()
            if args.sample
            else AwsSource(args.profile, args.region, args.terraform_dir)
        )
    except RuntimeError as exc:
        print(f"[오류] {exc}", file=sys.stderr)
        return 1

    # 127.0.0.1 고정. 로컬 전용 도구라 외부에 열지 않는다.
    server = ThreadingHTTPServer(
        ("127.0.0.1", args.port), partial(DashboardHandler, source=source)
    )

    print(f"대시보드: http://127.0.0.1:{args.port}  (Ctrl+C 로 종료)")
    if source.sample:
        print("샘플 모드: AWS 를 조회하지 않는다. 화면 데이터는 고정 예시다.")
    else:
        print(f"라이브 모드: {args.region} 의 Config·CloudWatch Logs 를 읽는다.")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n종료")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
