const scenarios = {
  ssh: {
    title: 'SSH Brute Force',
    subtitle: 'Repeated authentication failures are correlated into FAST rule 100200.',
    type: 'DETECTION REPLAY',
    model: ['Endpoint', 'Wazuh Agent', 'Wazuh Manager', 'Rule 100200', 'Incident'],
    pipeline: ['Endpoint', 'Agent', 'Manager', 'Detection', 'Incident'],
    result: {
      title: 'SSH Brute Force', severity: 'HIGH', rule: '100200', mitre: 'T1110', tactic: 'Credential Access',
      source: '203.0.113.42', agent: 'demo-linux-01', agentIp: '192.0.2.20', destination: '192.0.2.20:22', state: 'New'
    },
    events: [
      ['09:41:02', 'Endpoint telemetry observed', 'SSH authentication failure recorded', 'info'],
      ['09:41:03', 'Event received by Wazuh Agent', 'sshd decoder selected', 'info'],
      ['09:41:03', 'Event forwarded to Wazuh Manager', 'Authentication failure normalized', 'info'],
      ['09:41:04', 'Correlation started', 'Same source IP detected again', 'info'],
      ['09:41:04', 'Failure threshold reached', '5 authentication failures within 60 seconds', 'info'],
      ['09:41:05', 'Rule 100200 triggered', 'SSH brute force correlation promoted to alert', 'alert'],
      ['09:41:05', 'MITRE ATT&CK mapping generated', 'T1110 · Brute Force', 'success'],
      ['09:41:06', 'FAST incident created', 'Analyst state initialized as New', 'success']
    ],
    raw: { timestamp: '2026-09-30T09:41:05Z', rule: { id: '100200', level: 10 }, decoder: { name: 'sshd' }, source: { ip: '203.0.113.42' }, destination: { ip: '192.0.2.20', port: 22 }, mitre: { id: 'T1110', tactic: 'Credential Access' }, demo: true }
  },
  scan: {
    title: 'Port Scan',
    subtitle: 'Repeated port probe events are correlated into FAST rule 100211.',
    type: 'DETECTION REPLAY',
    model: ['Endpoint', 'Wazuh Agent', 'Wazuh Manager', 'Rule 100211', 'Incident'],
    pipeline: ['Endpoint', 'Agent', 'Manager', 'Detection', 'Incident'],
    result: {
      title: 'Port Scan', severity: 'HIGH', rule: '100211', mitre: 'T1046', tactic: 'Discovery',
      source: '203.0.113.77', agent: 'demo-linux-01', agentIp: '192.0.2.20', destination: '192.0.2.20', state: 'New'
    },
    events: [
      ['10:12:11', 'Port probe observed', 'Destination port 22', 'info'],
      ['10:12:12', 'Port probe observed', 'Destination port 80', 'info'],
      ['10:12:12', 'Port probe observed', 'Destination port 443', 'info'],
      ['10:12:13', 'Port probe observed', 'Destination port 445', 'info'],
      ['10:12:13', 'Port probe observed', 'Destination port 8080', 'info'],
      ['10:12:14', 'Port probe observed', 'Additional service endpoint reached', 'info'],
      ['10:12:15', 'Rule 100211 triggered', '8+ probes from the same source within 60 seconds', 'alert'],
      ['10:12:15', 'FAST incident created', 'MITRE T1046 · Network Service Scanning', 'success']
    ],
    raw: { timestamp: '2026-09-30T10:12:15Z', rule: { id: '100211', level: 7 }, decoder: { name: 'fast_portscan' }, source: { ip: '203.0.113.77' }, destination: { ip: '192.0.2.20' }, mitre: { id: 'T1046', tactic: 'Discovery' }, demo: true }
  },
  lolbin: {
    title: 'LOLBIN / Masquerading',
    subtitle: 'A suspicious process chain promotes a high-severity FAST detection.',
    type: 'DETECTION REPLAY',
    model: ['Endpoint', 'Wazuh Agent', 'Wazuh Manager', 'Rules 100220/100221', 'Incident'],
    pipeline: ['Endpoint', 'Agent', 'Manager', 'Detection', 'Incident'],
    result: {
      title: 'LOLBIN / Masquerading', severity: 'CRITICAL', rule: '100221', mitre: 'T1036.003', tactic: 'Defense Evasion',
      source: 'Local process', agent: 'demo-linux-01', agentIp: '192.0.2.20', destination: 'Host-local event', state: 'New'
    },
    events: [
      ['11:08:20', 'Process execution observed', 'Process name: httpd', 'info'],
      ['11:08:20', 'Unexpected executable path detected', '/tmp/httpd', 'info'],
      ['11:08:21', 'Parent rule 80792 matched', 'Suspicious process execution', 'info'],
      ['11:08:21', 'Rule 100220 triggered', 'Unexpected httpd path staged for correlation', 'info'],
      ['11:08:22', 'wget-style arguments detected', 'Process arguments match suspicious download pattern', 'info'],
      ['11:08:22', 'Rule 100221 triggered', 'High-confidence LOLBin / masquerading signal', 'alert'],
      ['11:08:22', 'MITRE ATT&CK mapping generated', 'T1036.003 · Rename System Utilities', 'success'],
      ['11:08:23', 'FAST incident created', 'Local process event — source is the agent, not an attacker IP', 'success']
    ],
    raw: { timestamp: '2026-09-30T11:08:22Z', rule: { id: '100221', level: 12 }, parent_rule: '100220', process: { name: 'httpd', executable: '/tmp/httpd', source_ip_origin: 'agent' }, agent: { id: 'demo-linux-01', ip: '192.0.2.20' }, mitre: { id: 'T1036.003', tactic: 'Defense Evasion' }, demo: true }
  },
  ioc: {
    title: 'IOC Feed Update',
    subtitle: 'Threat intelligence is collected, normalized, deduplicated and exported for Wazuh.',
    type: 'INTELLIGENCE REPLAY',
    model: ['Threat Feeds', 'TALON', 'SQLite', 'Validated CDB', 'Wazuh'],
    pipeline: ['Feeds', 'TALON', 'SQLite', 'CDB', 'Wazuh'],
    result: {
      title: 'IOC Feed Update', severity: 'SUCCESS', rule: 'TALON', mitre: '—', tactic: 'Threat Intelligence',
      source: '4 providers', agent: 'IOC pipeline', agentIp: '—', destination: 'Wazuh CDB', state: 'Completed'
    },
    events: [
      ['12:20:01', 'Feodo Tracker feed fetched', 'IPv4 indicators received', 'info'],
      ['12:20:02', 'URLhaus feed fetched', 'URL threat records normalized', 'info'],
      ['12:20:03', 'MalwareBazaar feed fetched', 'Hash metadata received', 'info'],
      ['12:20:04', 'Spamhaus DROP feed fetched', 'IPv4 / CIDR netblocks received', 'info'],
      ['12:20:05', 'TALON normalization completed', 'Provider-specific records mapped to common IOC schema', 'info'],
      ['12:20:06', 'Deduplication completed', '327 duplicate records removed', 'info'],
      ['12:20:07', 'SQLite database updated', '957 indicators validated for IPv4 / CIDR export', 'success'],
      ['12:20:08', 'Wazuh CDB export completed', 'Validated intelligence is ready for matching', 'success']
    ],
    raw: { timestamp: '2026-09-30T12:20:08Z', feeds: 4, received: 1284, duplicates: 327, validated: 957, database: 'SQLite', export: 'IPv4/CIDR CDB', status: 'success', demo: true }
  }
};

const state = { scenario: 'ssh', running: false, token: 0 };
const $ = (id) => document.getElementById(id);

function renderPipeline() {
  const data = scenarios[state.scenario];
  $('pipeline').innerHTML = data.pipeline.map((label, i) => `<div class="pipeline-node" data-step="${i}"><div class="pipeline-dot">${String(i + 1).padStart(2, '0')}</div><div class="pipeline-label">${label}</div><span class="pipeline-sub">${data.model[i] || ''}</span></div>`).join('');
}

function renderModel() {
  const data = scenarios[state.scenario];
  $('modelTitle').textContent = data.type === 'INTELLIGENCE REPLAY' ? 'Intelligence Pipeline' : 'Detection & Incident';
  $('modelFlow').innerHTML = data.model.map((item, i) => `<span class="model-node">${item}</span>${i < data.model.length - 1 ? '<span class="model-arrow">→</span>' : ''}`).join('');
}

function selectScenario(key) {
  state.scenario = key;
  document.querySelectorAll('.scenario').forEach((button) => button.classList.toggle('active', button.dataset.scenario === key));
  const data = scenarios[key];
  $('scenarioTitle').textContent = data.title;
  $('scenarioSubtitle').textContent = data.subtitle;
  $('eventCounter').textContent = `0 / ${data.events.length}`;
  $('resultState').textContent = 'WAITING';
  $('eventList').innerHTML = '<div class="empty-state">Choose “Run Replay” to start the read-only simulation.</div>';
  $('incidentContent').innerHTML = '<div class="result-placeholder"><span>◈</span><strong>Awaiting simulation</strong><p>The result will appear here after the replay reaches its final stage.</p></div>';
  $('rawEvent').textContent = JSON.stringify({ status: 'waiting', message: 'Run a replay to inspect sanitized event data.' }, null, 2);
  renderPipeline();
  renderModel();
}

function activateStep(index) {
  document.querySelectorAll('.pipeline-node').forEach((node, i) => {
    node.classList.toggle('active', i === index);
    node.classList.toggle('done', i < index);
  });
}

function addEvent(event, index, token) {
  if (token !== state.token) return;
  const [time, title, detail, kind] = event;
  const item = document.createElement('div');
  item.className = `event ${kind}`;
  item.innerHTML = `<span class="event-time">${time}</span><span class="event-mark">${kind === 'alert' ? '!' : '✓'}</span><span class="event-text"><b>${title}</b><small>${detail}</small></span>`;
  $('eventList').appendChild(item);
  $('eventList').scrollTop = $('eventList').scrollHeight;
  $('eventCounter').textContent = `${index + 1} / ${scenarios[state.scenario].events.length}`;
  const pipelineStep = Math.min(4, Math.floor(index / 2));
  activateStep(pipelineStep);
}

function showResult() {
  const data = scenarios[state.scenario];
  const r = data.result;
  $('resultState').textContent = r.severity === 'SUCCESS' ? 'COMPLETE' : 'INCIDENT CREATED';
  $('incidentContent').innerHTML = `<div class="incident-header"><div><div class="incident-title">${r.title}</div><div class="incident-type">${data.type} · READ ONLY</div></div><span class="severity ${r.severity === 'SUCCESS' ? 'info' : r.severity === 'HIGH' ? 'medium' : ''}">${r.severity}</span></div><div class="incident-grid"><div class="incident-field"><span>Rule / Pipeline</span><b>${r.rule}</b></div><div class="incident-field"><span>State</span><b>${r.state}</b></div><div class="incident-field"><span>Source</span><b>${r.source}</b></div><div class="incident-field"><span>Agent</span><b>${r.agent}</b></div><div class="incident-field"><span>Agent IP</span><b>${r.agentIp}</b></div><div class="incident-field"><span>Destination</span><b>${r.destination}</b></div></div><div class="mitre-box"><span>${r.mitre === '—' ? 'INTELLIGENCE CONTEXT' : 'MITRE ATT&CK'}</span><strong>${r.mitre === '—' ? 'Threat intelligence update' : r.mitre}</strong><small>${r.tactic}</small></div><div class="result-note">${state.scenario === 'lolbin' ? 'Local process event: FAST uses the agent IP as host context and does not label it as an attacker source IP.' : state.scenario === 'ioc' ? 'Validated indicators are exported as IPv4/CIDR CDB data for Wazuh matching.' : 'The replay shows the same logical stages used by FAST without executing an attack or changing infrastructure.'}</div>`;
  activateStep(4);
}

function replay() {
  state.token += 1;
  const token = state.token;
  state.running = true;
  $('replayBtn').disabled = true;
  $('replayBtn').textContent = '● Running…';
  $('eventList').innerHTML = '';
  $('incidentContent').innerHTML = '<div class="result-placeholder"><span>◌</span><strong>Processing replay…</strong><p>FAST is moving the event through the selected pipeline.</p></div>';
  $('resultState').textContent = 'PROCESSING';
  $('rawEvent').textContent = JSON.stringify({ status: 'processing', scenario: scenarios[state.scenario].title, demo: true }, null, 2);
  renderPipeline();
  activateStep(0);

  const data = scenarios[state.scenario];
  data.events.forEach((event, index) => {
    window.setTimeout(() => {
      addEvent(event, index, token);
      const raw = { timestamp: `2026-09-30T${event[0]}Z`, stage: event[1], detail: event[2], demo: true };
      $('rawEvent').textContent = JSON.stringify(raw, null, 2);
    }, 650 * (index + 1));
  });

  window.setTimeout(() => {
    if (token !== state.token) return;
    $('rawEvent').textContent = JSON.stringify(data.raw, null, 2);
    showResult();
    state.running = false;
    $('replayBtn').disabled = false;
    $('replayBtn').textContent = '↻ Replay';
  }, 650 * (data.events.length + 1));
}

function reset() {
  state.token += 1;
  state.running = false;
  $('replayBtn').disabled = false;
  $('replayBtn').textContent = '▶ Run Replay';
  selectScenario(state.scenario);
}

document.querySelectorAll('.scenario').forEach((button) => button.addEventListener('click', () => {
  if (!state.running) selectScenario(button.dataset.scenario);
}));
$('replayBtn').addEventListener('click', replay);
$('resetBtn').addEventListener('click', reset);

selectScenario('ssh');
