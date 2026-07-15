'use strict';

/* 탐지·조치 현황 대시보드 렌더러.
   의존성 없음. /api/snapshot 을 읽어 DOM 을 그린다. 자동 폴링은 하지 않는다
   (조치는 분 단위로 일어난다. 사람이 새로고침하는 편이 정직하다). */

// status → 색조. serve.py 가 내려주는 status 는 조치 Lambda 가 실제로 쓰는 값이다.
const STATUS_TONE = {
  applied: 't-accent',
  already_compliant: 't-idle',
  already_remediated: 't-idle',
  notified: 't-warn',
  skipped: 't-idle',
  error: 't-bad',
};

const STATUS_LABEL = {
  applied: '조치 적용',
  already_compliant: '이미 준수',
  already_remediated: '이미 조치됨',
  notified: '알림 발행',
  skipped: '건너뜀',
  error: '실패',
  rejected_no_confirmation: '거부 · 승인 없음',
  rejected_replacement_has_admin: '거부 · 교체안에 admin',
};

// 스트립 칸에 들어갈 짧은 이름. 카드 제목은 길어서 10px 칸에 안 들어간다.
const SHORT_NAME = {
  's3-public-access': 'S3 공개',
  'iam-excessive-privilege': 'IAM 권한',
  's3-kms-encryption': 'S3 암호화',
  'ebs-encryption-default': 'EBS 암호화',
};

const RANGE_LABEL = { '1h': '최근 1시간', '24h': '최근 24시간', '7d': '최근 7일' };

const REPO_BASE = 'https://github.com/ham22e/aws-sec-autofix/blob/main/';

let currentRange = '24h';
let firstRender = true;

// --- 작은 헬퍼 -------------------------------------------------------
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

function statusTone(status) {
  if (STATUS_TONE[status]) return STATUS_TONE[status];
  // 승인 조치의 거부(rejected_*)는 안전장치가 작동한 것이지 실패가 아니다.
  if (status.startsWith('rejected')) return 't-warn';
  return 't-idle';
}

function statusLabel(status) {
  return STATUS_LABEL[status] || status;
}

function complianceView(state) {
  if (state === 'COMPLIANT') return { label: '준수', tone: 't-ok' };
  if (state === 'NON_COMPLIANT') return { label: '미준수', tone: 't-bad' };
  return { label: '평가 대기', tone: 't-idle' };
}

// ARN 은 앞부분(파티션·리전·계정 ID)이 모든 행에서 똑같아서 읽는 데 보탬이 안 되고
// 컬럼만 넓힌다. 실제로 구분되는 뒷부분만 보여준다. 전체 값은 title 로 남긴다.
//   arn:aws:iam::123456789012:policy/autofix-vulnerable-admin-policy
//     → policy/autofix-vulnerable-admin-policy
function shortenArn(value) {
  if (!value.startsWith('arn:')) return value;
  const tail = value.split(':').pop();
  return tail || value;
}

function pad(n) {
  return String(n).padStart(2, '0');
}

function formatTime(iso) {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return `${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

// --- 조치 흐름 리본 --------------------------------------------------
// 탐지 → 조치 → 준수. 현재 상태까지 노드를 채운다. 승인 기반 통제는 조치 노드가
// 마름모다(자동 조치와 형태로 구분되므로 색을 못 봐도 읽힌다).
function buildRibbon(scenario) {
  const evaluated = scenario.compliance !== null;
  const compliant = scenario.compliance === 'COMPLIANT';
  const approval = scenario.mode === 'approval';

  const events = Object.values(scenario.event_counts).reduce((a, b) => a + b, 0);
  const failed = scenario.last_event && scenario.last_event.status === 'error';

  const remediated = events > 0;
  const remediationTone = failed ? 't-bad' : 't-accent';

  // 조치 이벤트가 있다는 것 자체가 탐지의 증거다. 조치 Lambda 는 Config 규칙이
  // NON_COMPLIANT 로 바뀔 때만 트리거되기 때문이다. 조치는 끝났는데 Config 가 아직
  // 재평가 전(INSUFFICIENT_DATA)인 구간에서 "탐지 안 됨 + 조치됨"으로 보이면 안 된다.
  const detected = evaluated || remediated;

  const ribbon = el('div', 'ribbon');

  const detect = el('div', `step${detected ? ' on t-accent' : ''}`);
  detect.appendChild(el('i'));
  detect.appendChild(el('span', null, '탐지'));

  const rail1 = el('div', `rail${remediated ? ' on t-accent' : ''}`);

  let remediateClass = 'step';
  if (approval) remediateClass += ' approval';
  if (remediated) remediateClass += ` on ${remediationTone}`;
  // 미준수인데 아직 조치가 안 끝났다면 그 노드가 지금 주목할 지점이다.
  if (evaluated && !compliant) remediateClass += ` pulse ${remediationTone}`;

  const remediate = el('div', remediateClass);
  remediate.appendChild(el('i'));
  remediate.appendChild(el('span', null, approval ? '승인 조치' : '조치'));

  const rail2 = el('div', `rail${compliant ? ' on t-ok' : ''}`);

  const done = el('div', `step${compliant ? ' on t-ok' : ''}`);
  done.appendChild(el('i'));
  done.appendChild(el('span', null, '준수'));

  ribbon.append(detect, rail1, remediate, rail2, done);
  return ribbon;
}

// --- 시나리오 카드 ---------------------------------------------------
function buildCard(scenario, index) {
  const view = complianceView(scenario.compliance);

  const card = el('article', `card ${view.tone}`);
  card.style.setProperty('--i', index);

  const head = el('div', 'card-head');
  const heading = el('div');
  heading.appendChild(el('h3', null, scenario.title));
  heading.appendChild(el('code', 'card-rule', scenario.config_rule));
  head.appendChild(heading);
  head.appendChild(el('span', 'badge', view.label));
  card.appendChild(head);

  card.appendChild(buildRibbon(scenario));

  if (scenario.error) {
    card.appendChild(el('p', 'card-error', scenario.error));
  }

  if (scenario.violating_resources.length > 0) {
    const box = el('div', 'violations');
    box.appendChild(el('p', null, '지금 위반 중인 리소스'));
    const list = el('ul');
    scenario.violating_resources.forEach((id) => {
      list.appendChild(el('li', 'mono', id));
    });
    box.appendChild(list);
    card.appendChild(box);
  }

  const foot = el('div', 'card-foot');
  const pills = el('div', 'pills');
  const entries = Object.entries(scenario.event_counts);

  if (entries.length === 0) {
    pills.appendChild(el('span', 'quiet', '이 기간에 조치 이벤트 없음'));
  } else {
    entries
      .sort((a, b) => b[1] - a[1])
      .forEach(([status, count]) => {
        pills.appendChild(
          el('span', `pill ${statusTone(status)}`, `${statusLabel(status)} ${count}`)
        );
      });
  }
  foot.appendChild(pills);

  const runbook = el('a', 'runbook', '런북 보기');
  runbook.href = REPO_BASE + scenario.runbook;
  runbook.target = '_blank';
  runbook.rel = 'noopener';
  foot.appendChild(runbook);

  card.appendChild(foot);
  return card;
}

// --- KPI -------------------------------------------------------------
function renderCompliance(data) {
  const { summary, scenarios } = data;

  document.getElementById('rate').textContent =
    summary.compliance_rate === null ? '–' : summary.compliance_rate;

  const strip = document.getElementById('strip');
  strip.replaceChildren();
  scenarios.forEach((s) => {
    const view = complianceView(s.compliance);
    const cell = el('figure', view.tone);
    cell.title = `${s.title}: ${view.label}`;
    cell.appendChild(el('div', 'seg'));
    cell.appendChild(el('figcaption', null, SHORT_NAME[s.control] || s.control));
    strip.appendChild(cell);
  });

  const tally = document.getElementById('tally');
  tally.replaceChildren();
  [
    ['준수', summary.compliant_rules, 't-ok'],
    ['미준수', summary.non_compliant_rules, 't-bad'],
    ['평가 대기', summary.pending_rules, 't-idle'],
  ].forEach(([label, count, tone]) => {
    const pair = el('div', tone);
    pair.appendChild(el('dt', null, label));
    pair.appendChild(el('dd', null, count));
    tally.appendChild(pair);
  });
}

function renderEvents(data) {
  const counts = data.summary.event_counts;
  const entries = Object.entries(counts).sort((a, b) => b[1] - a[1]);
  const total = entries.reduce((sum, [, count]) => sum + count, 0);

  document.getElementById('event-total').textContent = total;
  document.getElementById('range-note').textContent = RANGE_LABEL[data.range];

  const stack = document.getElementById('stack');
  stack.replaceChildren();
  entries.forEach(([status, count]) => {
    const bar = el('span', statusTone(status));
    bar.style.width = `${(count / total) * 100}%`;
    bar.title = `${statusLabel(status)} ${count}`;
    stack.appendChild(bar);
  });

  const tally = document.getElementById('event-tally');
  tally.replaceChildren();
  if (entries.length === 0) {
    tally.appendChild(el('div', 'quiet', '이 기간에 기록된 조치가 없다. 기간을 넓혀 보라.'));
    return;
  }
  entries.forEach(([status, count]) => {
    const pair = el('div', statusTone(status));
    pair.appendChild(el('dt', null, statusLabel(status)));
    pair.appendChild(el('dd', null, count));
    tally.appendChild(pair);
  });
}

function renderTimeline(rows) {
  const body = document.getElementById('timeline');
  body.replaceChildren();

  if (rows.length === 0) {
    const cell = el('td', 'empty', '이 기간에 조치 이벤트가 없다. 기간을 넓히거나, 취약 리소스를 유발해 파이프라인을 돌려 보라.');
    cell.colSpan = 5;
    const row = el('tr');
    row.appendChild(cell);
    body.appendChild(row);
    return;
  }

  rows.forEach((row) => {
    const tr = el('tr');

    const when = el('td', 'when', formatTime(row.timestamp));
    when.title = row.timestamp;
    tr.appendChild(when);

    tr.appendChild(el('td', 'what', row.control));

    const status = el('td', 'state');
    status.appendChild(
      el('span', `pill ${statusTone(row.status)}`, statusLabel(row.status))
    );
    tr.appendChild(status);

    const target = el('td', 'target mono', shortenArn(row.resource));
    target.title = row.resource;
    tr.appendChild(target);

    tr.appendChild(el('td', 'detail', row.detail));

    body.appendChild(tr);
  });
}

function renderAlerts(messages) {
  const box = document.getElementById('alerts');
  box.replaceChildren();
  box.hidden = messages.length === 0;
  messages.forEach((message) => box.appendChild(el('p', null, message)));
}

// --- 조립 ------------------------------------------------------------
function render(data) {
  document.getElementById('meta').textContent =
    `${data.region} · ${formatTime(data.generated_at)} 기준 · ${RANGE_LABEL[data.range]}`;

  document.getElementById('sample-banner').hidden = !data.sample;

  renderAlerts(data.errors);
  renderCompliance(data);
  renderEvents(data);

  const cards = document.getElementById('cards');
  cards.classList.toggle('intro', firstRender);
  cards.replaceChildren();
  data.scenarios.forEach((s, i) => cards.appendChild(buildCard(s, i)));
  firstRender = false;

  renderTimeline(data.timeline);

  const link = document.getElementById('cw-link');
  if (data.cloudwatch_dashboard_url) {
    link.href = data.cloudwatch_dashboard_url;
    link.hidden = false;
  }
}

async function load() {
  const button = document.getElementById('refresh');
  button.disabled = true;
  button.textContent = '불러오는 중';

  try {
    const response = await fetch(`/api/snapshot?range=${currentRange}`);
    if (!response.ok) throw new Error(`HTTP ${response.status}`);
    render(await response.json());
  } catch (error) {
    renderAlerts([`스냅샷을 불러오지 못했다: ${error.message}. serve.py 가 실행 중인지 확인하라.`]);
    document.getElementById('meta').textContent = '연결 실패';
  } finally {
    button.disabled = false;
    button.textContent = '새로고침';
  }
}

document.querySelectorAll('.rangepick button').forEach((button) => {
  button.addEventListener('click', () => {
    currentRange = button.dataset.range;
    document.querySelectorAll('.rangepick button').forEach((other) => {
      other.setAttribute('aria-pressed', String(other === button));
    });
    load();
  });
});

document.getElementById('refresh').addEventListener('click', load);

load();
