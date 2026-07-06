"""준수율 발행 함수: AWS Config 규칙의 준수 상태를 CloudWatch 메트릭으로 낸다.

가시화 대시보드의 "준수율" 위젯을 채우기 위한 소형 함수다. 조치 로그에는
준수율(COMPLIANT/NON_COMPLIANT 비율)이 없어서, EventBridge 스케줄이 이 함수를
주기 호출하면 함수가 프로젝트 Config 규칙의 현재 준수 상태를 읽어
namespace AutoFix/Compliance 로 커스텀 메트릭을 발행한다.

발행 메트릭:
- RuleCompliance (dim ConfigRuleName): 규칙별 1(COMPLIANT)/0(NON_COMPLIANT).
  INSUFFICIENT_DATA·NOT_APPLICABLE 는 판정 불가라 datapoint 를 내지 않는다.
- ComplianceRate: 전체 준수율(%) = 100 * compliant / (compliant + non_compliant).
  분모가 0(아직 평가 전)이면 내지 않는다.
- CompliantRules / NonCompliantRules: 각 상태 규칙 수(위젯 보조용).

원칙:
- 멱등적: 조회만 하고 계정 설정을 바꾸지 않는다(비파괴, 읽기 전용).
- 관측 가능: 조치 Lambda 와 같은 규약으로 JSON 한 줄 로그도 남긴다.
"""

import datetime
import json
import os

import boto3

config = boto3.client("config")
cloudwatch = boto3.client("cloudwatch")

NAMESPACE = "AutoFix/Compliance"

# 판정 대상 규칙 이름(콤마 구분). 루트에서 각 시나리오 모듈의 config_rule_name 을 모아 전달.
RULE_NAMES = [n for n in os.environ.get("CONFIG_RULE_NAMES", "").split(",") if n]


def _log(**fields):
    """준수율 스냅샷을 JSON 한 줄로 표준출력에 남긴다(→ CloudWatch Logs)."""
    record = {"event_type": "compliance_snapshot"}
    record.update(fields)
    print(json.dumps(record, ensure_ascii=False, sort_keys=True))


def _now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def lambda_handler(event, context):
    ts = _now()

    # 대상 규칙이 없으면 종료한다. describe_compliance_by_config_rule 에 빈 목록을 주면
    # AWS Config 가 "계정 전체 규칙"으로 해석해 프로젝트 밖 규칙까지 준수율에 섞인다
    # (루트가 넘기는 config_rule_names 가 비는 경우를 방어).
    if not RULE_NAMES:
        _log(status="skipped", reason="no_config_rule_names", timestamp=ts)
        return {"compliant": 0, "non_compliant": 0, "rate": None}

    try:
        # describe_compliance_by_config_rule 는 한 번에 최대 25개 규칙을 받는다(대상이 소수라
        # 단일 페이지로 충분. 규칙이 페이지 한도를 넘으면 NextToken 처리를 추가한다).
        resp = config.describe_compliance_by_config_rule(ConfigRuleNames=RULE_NAMES)

        metric_data = []
        compliant = 0
        non_compliant = 0

        for item in resp.get("ComplianceByConfigRules", []):
            name = item["ConfigRuleName"]
            compliance_type = item.get("Compliance", {}).get("ComplianceType")

            if compliance_type == "COMPLIANT":
                compliant += 1
                value = 1
            elif compliance_type == "NON_COMPLIANT":
                non_compliant += 1
                value = 0
            else:
                # INSUFFICIENT_DATA / NOT_APPLICABLE: 판정 불가 → datapoint 생략.
                continue

            metric_data.append({
                "MetricName": "RuleCompliance",
                "Dimensions": [{"Name": "ConfigRuleName", "Value": name}],
                "Value": value,
                "Unit": "None",
            })

        evaluated = compliant + non_compliant
        rate = round(100.0 * compliant / evaluated, 1) if evaluated else None

        metric_data.append({"MetricName": "CompliantRules", "Value": compliant, "Unit": "Count"})
        metric_data.append({"MetricName": "NonCompliantRules", "Value": non_compliant, "Unit": "Count"})
        if rate is not None:
            metric_data.append({"MetricName": "ComplianceRate", "Value": rate, "Unit": "Percent"})

        # put_metric_data 는 호출당 최대 1000개 MetricData(여긴 수개)라 한 번에 보낸다.
        cloudwatch.put_metric_data(Namespace=NAMESPACE, MetricData=metric_data)

        # rules_configured=설정된 규칙 수, rules_evaluated=실제 판정된 수(INSUFFICIENT 제외).
        _log(
            compliant=compliant,
            non_compliant=non_compliant,
            rate=rate,
            rules_configured=len(RULE_NAMES),
            rules_evaluated=evaluated,
            timestamp=ts,
        )
        return {"compliant": compliant, "non_compliant": non_compliant, "rate": rate}

    except Exception as exc:  # noqa: BLE001 발행 실패도 구조화 로그로 남긴다.
        _log(status="error", error_type=type(exc).__name__, error=str(exc), timestamp=ts)
        raise
