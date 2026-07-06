"""Firehose 변환 함수: CloudWatch Logs 봉투를 벗겨 원본 로그만 남긴다.

조치 Lambda 로그 그룹의 구독 필터(subscription filter)가 Kinesis Firehose 로
로그를 보내면, 데이터는 gzip 압축된 CloudWatch Logs 봉투 형태로 온다:
    {"messageType":"DATA_MESSAGE","logGroup":...,"logStream":...,
     "logEvents":[{"id":..,"timestamp":..,"message":"<원본 로그 한 줄>"}, ...]}

이 함수는 봉투를 풀어 각 logEvent 의 message(=조치 Lambda 가 남긴 JSON 한 줄)만
개행으로 이어 붙여 S3 로 흘려보낸다. 그 결과 로그 레이크에는 이미 정규화된
조치 JSON 이 그대로 쌓여, Glue/Athena 가 추가 파싱 없이 조회할 수 있다.

Firehose 변환 계약(공식):
- 입력: event["records"] = [{"recordId","data"(base64 gzip 봉투),...}, ...]
- 출력: {"records":[{"recordId","result","data"(base64)}, ...]}
  result: "Ok"(변환 성공) / "Dropped"(버림) / "ProcessingFailed"(실패)
- CONTROL_MESSAGE(도달성 점검용)는 실제 로그가 아니므로 Dropped 한다.
"""

import base64
import gzip
import json


def _transform_record(record):
    payload = base64.b64decode(record["data"])
    data = json.loads(gzip.decompress(payload))

    message_type = data.get("messageType")

    # 도달성 점검 메시지는 실제 로그가 아니므로 버린다.
    if message_type == "CONTROL_MESSAGE":
        return {"recordId": record["recordId"], "result": "Dropped"}

    if message_type != "DATA_MESSAGE":
        # 예상치 못한 봉투 타입은 손상 없이 버린다(파이프라인 중단 방지).
        return {"recordId": record["recordId"], "result": "Dropped"}

    # 각 logEvent 의 원본 message 한 줄씩을 개행으로 이어 붙인다.
    lines = "".join(
        f"{event['message']}\n" for event in data.get("logEvents", [])
    )

    if not lines:
        return {"recordId": record["recordId"], "result": "Dropped"}

    return {
        "recordId": record["recordId"],
        "result": "Ok",
        "data": base64.b64encode(lines.encode("utf-8")).decode("utf-8"),
    }


def lambda_handler(event, context):
    # 레코드별로 격리한다. 한 레코드가 손상돼도 그 레코드만 ProcessingFailed 로
    # 표시하고 나머지 정상 레코드는 통과시킨다(배치 전체 실패·재시도 방지).
    output = []
    for record in event["records"]:
        try:
            output.append(_transform_record(record))
        except Exception:  # noqa: BLE001 손상 레코드 1건이 배치를 막지 않게 격리.
            output.append({"recordId": record["recordId"], "result": "ProcessingFailed"})
    return {"records": output}
