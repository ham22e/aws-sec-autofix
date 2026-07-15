# 웹 대시보드 (로컬 실행)

탐지·조치 현황을 시나리오 중심으로 보여주는 웹 대시보드다.
CloudWatch 대시보드(`terraform/modules/dashboard/`)와 **병행 운영**한다.

## CloudWatch 대시보드와 무엇이 다른가

같은 사실을 보되 **소스가 다르다.**

| | CloudWatch 대시보드 | 이 웹 대시보드 |
|---|---|---|
| 데이터 소스 | metric filter 가 만든 커스텀 메트릭 | AWS Config + CloudWatch Logs **직접 조회** |
| 볼 수 있는 것 | control·status 별 집계 | 집계 + **위반 리소스 ID, 적용된 KMS 키, 정책 버전** |
| 접근 | AWS 콘솔 로그인 필요 | 로컬 브라우저 |

메트릭은 차원(control·status)만 담을 수 있어서 "지금 **어느 버킷이** 위반 중인가"를
잃는다. Config 의 `GetComplianceDetailsByConfigRule` 과 조치 로그 원본 JSON 을 직접
읽으면 그 정보가 산다. 그래서 이 대시보드는 메트릭을 우회한다.

**AWS 리소스를 새로 만들지 않는다.** 읽기 전용 API 3종만 호출한다. 비용 0원이고
`terraform destroy` 에 영향이 없다.

## 실행

```bash
cd dashboard
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

```bash
# 라이브 (terraform apply 가 끝난 뒤)
python serve.py --profile <프로필>

# 샘플 데이터 (AWS 불필요, 배포 전에도 화면을 볼 수 있다)
python serve.py --sample
```

`http://127.0.0.1:8000` 으로 접속한다. 서버는 127.0.0.1 에만 바인드한다.

| 인자 | 기본값 | 설명 |
|---|---|---|
| `--profile` | (기본 자격증명 체인) | AWS CLI 프로필 이름 |
| `--region` | `ap-northeast-2` | 조회할 리전 |
| `--port` | `8000` | 바인드할 포트 |
| `--terraform-dir` | `../terraform` | `terraform output` 을 읽을 디렉터리 |
| `--sample` | 꺼짐 | AWS 대신 `sample-snapshot.json` 을 쓴다 |

## 화면 읽는 법

**조치 흐름 리본**이 각 시나리오 카드의 핵심이다. `탐지 → 조치 → 준수` 3단계 중
현재 어디까지 왔는지를 보여준다.

- 원(●) = 자동 조치, 마름모(◆) = **사람 승인이 필요한 조치**(IAM). 색이 아니라 형태로
  구분하므로 색을 못 봐도 읽힌다.
- 조치 노드가 **빨강**이면 조치가 실패한 것이다(최근 이벤트가 `error`).
- 미준수인 통제는 조치 노드가 깜박인다. 지금 주목할 지점이라는 뜻이다.

준수율 공식은 `lambda/compliance-metrics/handler.py` 와 같다
(`100 × 준수 / (준수 + 미준수)`, `INSUFFICIENT_DATA` 는 분모에서 제외).
**두 대시보드가 다른 준수율을 보이면 둘 중 하나가 틀린 것이다.**

## 필요한 IAM 권한

읽기 전용 3종이다.

- `config:DescribeComplianceByConfigRule`
- `config:GetComplianceDetailsByConfigRule`
- `logs:FilterLogEvents`

`docs/deploy-iam-policy.json` 의 배포 주체 권한(`config:*`, `logs:*`)에 이미 포함돼
있다. **별도 정책을 만들 필요가 없다.**

리소스 이름은 하드코딩하지 않는다. `terraform output -json` 으로 Config 규칙 4개와
조치 Lambda 5개의 이름을 읽어 온다. `project_name` 을 바꿔도 그대로 동작한다.

## 문제 해결

**`terraform output 에 필요한 값이 없다`**
아직 `terraform apply` 를 하지 않았거나, `--terraform-dir` 이 잘못됐다.
배포 전이라면 `--sample` 로 화면만 볼 수 있다.

**`AWS 자격증명 확인 실패`**
`--profile` 값이 틀렸거나 자격증명이 만료됐다. 서버는 시작할 때 자격증명을
검증한다(첫 요청에서야 터지지 않도록).

**시나리오 카드가 전부 "평가 대기"**
Config 규칙이 아직 평가되지 않았다. Recorder 가 켜진 뒤 첫 평가까지 몇 분 걸린다.
`INSUFFICIENT_DATA` 는 판정 불가라 준수율 분모에서 뺀다.

**타임라인이 비어 있음**
조치 Lambda 가 아직 한 번도 실행되지 않았으면 로그 그룹 자체가 없다(오류가 아니라
조치 이력이 없는 것이다). 기간을 7일로 넓히거나, `docs/guide/` 의 검증 가이드대로
취약 리소스를 유발해 파이프라인을 한 바퀴 돌려 보라.

## 구성

```
dashboard/
├── serve.py               # 로컬 HTTP 서버 + AWS 읽기 전용 조회
├── sample-snapshot.json   # --sample 모드용 고정 데이터
├── requirements.txt
└── static/                # 의존성 없는 바닐라 HTML/CSS/JS
    ├── index.html
    ├── app.js
    └── style.css
```

`sample-snapshot.json` 은 완성된 API 응답이 아니라 **원본 재료**(terraform output +
Config 상태 + 조치 로그 원본 JSON)를 담는다. `serve.py` 가 라이브와 똑같은 조립
코드를 태우므로 두 모드의 응답 스키마가 어긋날 수 없다.
