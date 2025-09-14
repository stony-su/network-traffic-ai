let graphData = null;

async function loadAnalysis(){
  try {
    const res = await fetch('/api/analysis');
    const data = await res.json();
    if(data.graph){
      graphData = data.graph;
      renderGraph(graphData);
      renderAnomalies(data.anomalies || []);
      renderEvents(data.recent_events || []);
      renderAttackSummary(data);
      renderTimeline(data.timeline || []);
      updateStats();
    } else if(data.error){
      console.error('Analysis error', data.error);
    }
  } catch(e){ console.error(e); }
}

async function reloadAnalysis(){
  await fetch('/api/reload', {method:'POST'});
  await loadAnalysis();
}

function updateStats(){
  if(!graphData) return;
  const hosts = graphData.nodes.filter(n=>n.type==='host').length;
  const alerts = graphData.nodes.filter(n=>n.type==='alert').length;
  const edges = graphData.edges.length;
  document.getElementById('stats').textContent = `Hosts: ${hosts} | Alerts: ${alerts} | Edges: ${edges}`;
}

function renderAnomalies(anoms){
  const el = document.getElementById('anomalies');
  if(!anoms.length){
    el.innerHTML = '<div class="empty">No anomalies</div>';
    return;
  }
  const rows = anoms.map(a=>{
    let sevClass = 'sev-low';
    if(a.score >= 6) sevClass = 'sev-high'; else if(a.score >=4) sevClass='sev-med';
    return `<tr>
      <td class="mono ip">${a.entity_id}</td>
      <td><span class="badge ${sevClass}">${a.score.toFixed(2)}</span></td>
      <td class="reason">${a.reason}</td>
    </tr>`;
  }).join('');
  el.innerHTML = `<table class="mini-table"><thead><tr><th>Source</th><th>Z</th><th>Reason</th></tr></thead><tbody>${rows}</tbody></table>`;
}

function renderEvents(events){
  const el = document.getElementById('events');
  if(!events.length){ el.innerHTML='<div class="empty">No recent events</div>'; return; }
  el.innerHTML = events.map(e=>{
    const pri = e.priority!=null?`P${e.priority}`:'P?';
    const flow = `${e.src_ip||'?'}${e.src_port?':'+e.src_port:''} → ${e.dst_ip||'?'}${e.dst_port?':'+e.dst_port:''}`;
    const time = new Date(e.timestamp).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit', second:'2-digit'});
    return `<div class="event-row">
      <div class="col time">${time}</div>
      <div class="col pri pri-${e.priority||'x'}">${pri}</div>
      <div class="col flow mono">${flow}</div>
      <div class="col sig" title="${e.signature}">${e.signature}</div>
    </div>`;
  }).join('');
}

function renderAttackSummary(data){
  const el = document.getElementById('attack-summary');
  if(!el) return;
  if(!data.most_aggressive_attacker){
    el.innerHTML = '<div class="empty">No attacker data</div>';
    return;
  }
  el.innerHTML = `
    <div class="metric-grid">
      <div class="metric">
        <div class="label">Top Attacker</div>
        <div class="value mono">${data.most_aggressive_attacker}</div>
        <div class="sub">${data.most_aggressive_attacker_count} evts</div>
      </div>
      <div class="metric">
        <div class="label">Top Defender</div>
        <div class="value mono">${data.most_attacked_defender||'N/A'}</div>
        <div class="sub">${data.most_attacked_defender_count||0} evts</div>
      </div>
    </div>`;
}

function renderTimeline(entries){
  const el = document.getElementById('timeline');
  if(!el) return;
  if(!entries.length){ el.innerHTML='<li class="empty">No timeline entries</li>'; return; }
  el.innerHTML = entries.map(t=>{
    const start = new Date(t.start).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
    const end = new Date(t.end).toLocaleTimeString([], {hour:'2-digit', minute:'2-digit'});
    const durMs = (new Date(t.end) - new Date(t.start));
    const mins = Math.max( (durMs/60000).toFixed(1), 0.1);
    return `<li class="timeline-entry">
      <span class="badge count">${t.count}</span>
      <span class="mono flow">${t.src_ip||'?'} → ${t.dst_ip||'?'}</span>
      <span class="sig" title="${t.signature}">${t.signature}</span>
      <span class="range">${start}–${end} <span class="dur">(${mins}m)</span></span>
    </li>`;
  }).join('');
}

/**
 * Analyze events for weak security practices & anomalies.
 * Expected event fields (if present):
 *  src_ip, dst_ip, src_port, dst_port, proto, payload, user_agent, timestamp
 */
function analyzeWeakPractices(events) {
  const metrics = {
    cleartext_admin: 0,
    telnet: 0,
    ftp: 0,
    basic_auth: 0,
    plain_http_pw: 0,
    snmp_public: 0,
    smb_external: 0,
    db_exposed: 0,
    outdated_tls: 0
  };

  const legacyClientPatterns = [
    /MSIE\s+[67]\./i,
    /Java\/1\.6/i,
    /OpenSSL\/0\.9\.8/i,
    /Windows NT 5\./i,
    /FlashPlayer/i
  ];
  const legacyClientsCounter = {};

  const scanners = {}; // src_ip -> { ports:Set, count:int }

  const privRE = /^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|127\.|169\.254\.)/;
  const isPrivate = ip => privRE.test(ip || '');

  const pwParam = /(password|passwd|pwd|login)=([^\s&#]{1,40})/i;

  for (const ev of events) {
    const dp = Number(ev.dst_port);
    const sp = Number(ev.src_port);
    const src = ev.src_ip || ev.src || ev.client || '';
    const dst = ev.dst_ip || ev.dst || '';
    const proto = (ev.proto || ev.protocol || '').toUpperCase();
    const payload = (ev.payload || ev.data || '');
    const userAgent = ev.user_agent || ev.ua || '';

    // Track scanners
    if (src) {
      if (!scanners[src]) scanners[src] = { ports: new Set(), count: 0 };
      if (dp) scanners[src].ports.add(dp);
      scanners[src].count++;
    }

    // Cleartext admin protocols
    if ([23, 513, 514].includes(dp)) {
      metrics.cleartext_admin++;
      if (dp === 23) metrics.telnet++;
    }
    // FTP
    if ([20, 21].includes(dp)) metrics.ftp++;

    // Basic Auth (HTTP)
    if (/Authorization:\s*Basic\s+[A-Za-z0-9+/=]+/i.test(payload)) metrics.basic_auth++;

    // Plain HTTP password submission (no TLS context + password param)
    if (pwParam.test(payload) && !/TLS|SSL/i.test(payload) && /HTTP\/1\.[01]/.test(payload)) {
      metrics.plain_http_pw++;
    }

    // SNMP v1/v2c public community
    if ((dp === 161 || dp === 162) && /public/i.test(payload) && /community/i.test(payload)) {
      metrics.snmp_public++;
    }

    // SMB external exposure
    if (dp === 445 && src && dst && !(isPrivate(src) && isPrivate(dst))) {
      metrics.smb_external++;
    }

    // DB ports exposed externally
    if ([1433, 1521, 3306].includes(dp) && isPrivate(src) && !isPrivate(dst)) {
      metrics.db_exposed++;
    }

    // Outdated TLS handshake indicator (very heuristic if payload has "SSLv3" or "SSLv2" or "TLSv1 ")
    if (/SSLv2|SSLv3|TLSv1[^.]/.test(payload)) {
      metrics.outdated_tls++;
    }

    // Legacy user agents
    if (userAgent) {
      legacyClientPatterns.forEach(re => {
        if (re.test(userAgent)) {
          const k = re.source;
          legacyClientsCounter[k] = (legacyClientsCounter[k] || 0) + 1;
        }
      });
    }
  }

  // Derive scanners (threshold = > 30 distinct dest ports or > 400 flows)
  const scannerList = Object.entries(scanners)
    .filter(([ip, obj]) => obj.ports.size > 30 || obj.count > 400)
    .map(([ip, obj]) => ({ ip, distinctPorts: obj.ports.size, flows: obj.count }))
    .sort((a,b) => b.distinctPorts - a.distinctPorts || b.flows - a.flows);

  const legacyClients = Object.entries(legacyClientsCounter)
    .map(([pattern, count]) => ({ pattern, count }))
    .sort((a,b) => b.count - a.count);

  return { metrics, scannerList, legacyClients };
}

function renderSecurityFindings(events) {
  const { metrics, scannerList, legacyClients } = analyzeWeakPractices(events);

  // Summary boxes
  const summaryEl = document.getElementById('findings-summary');
  if (!summaryEl) return;
  const order = [
    ['cleartext_admin','Cleartext Admin'],
    ['telnet','Telnet'],
    ['ftp','FTP'],
    ['basic_auth','HTTP Basic'],
    ['plain_http_pw','Plain PW Posts'],
    ['snmp_public','SNMP Public'],
    ['smb_external','SMB External'],
    ['db_exposed','DB Exposed'],
    ['outdated_tls','Outdated TLS']
  ];
  summaryEl.innerHTML = order.map(([k,label]) => {
    const val = metrics[k];
    const cls = val > 0
      ? (['cleartext_admin','telnet','plain_http_pw','smb_external','db_exposed'].includes(k) ? 'finding-box bad' :
         (['basic_auth','snmp_public','outdated_tls','ftp'].includes(k) ? 'finding-box warn' : 'finding-box'))
      : 'finding-box';
    return `<div class="${cls}">
        <div class="label">${label}</div>
        <div class="value">${val}</div>
      </div>`;
  }).join('');

  // Bar chart
  const chartEl = document.getElementById('findings-chart');
  const data = order.map(([k,label]) => ({ key:k, label, value: metrics[k] })).filter(d => d.value > 0);
  const max = Math.max(...data.map(d => d.value), 1);
  chartEl.innerHTML = data.length === 0
    ? '<div style="font-size:11px;opacity:0.6;">No weak practices detected in current sample.</div>'
    : data.map(d => {
        const hPct = (d.value / max) * 100;
        const sev = d.value === 0 ? 'good'
          : (['cleartext_admin','telnet','plain_http_pw','smb_external','db_exposed'].includes(d.key) ? 'bad'
             : (['basic_auth','snmp_public','outdated_tls','ftp'].includes(d.key) ? 'warn' : 'good'));
        return `<div class="bar-col" title="${d.label}: ${d.value}">
            <div class="bar ${sev}" style="height:${Math.max(8,hPct)}%;"><span style="padding:2px;">${d.value}</span></div>
            <div class="bar-label">${d.label}</div>
        </div>`;
      }).join('');

  // Scanners table
  const scanBody = document.querySelector('#scanners-table tbody');
  scanBody.innerHTML = scannerList.length
    ? scannerList.slice(0,30).map(s => `<tr>
        <td class="mono">${s.ip}</td>
        <td>${s.distinctPorts}</td>
        <td>${s.flows}</td>
      </tr>`).join('')
    : '<tr><td colspan="3" class="empty">None detected (threshold >30 ports or >400 flows)</td></tr>';

  // Legacy clients table
  const lcBody = document.querySelector('#legacy-clients-table tbody');
  lcBody.innerHTML = legacyClients.length
    ? legacyClients.map(l => `<tr>
        <td>${l.pattern}</td>
        <td>${l.count}</td>
      </tr>`).join('')
    : '<tr><td colspan="2" class="empty">No legacy user agents matched.</td></tr>';
}

// Hook into existing data load (adjust to your actual fetch / update logic)
function integrateSecurityFindingsHook() {
  // If you already have a global events array, call renderSecurityFindings(events)
  if (window.allEvents) {
    renderSecurityFindings(window.allEvents);
  } else if (window.recentEvents) {
    // fallback
    renderSecurityFindings(window.recentEvents);
  } else {
    // If events arrive asynchronously, you can attach after fetch
    document.addEventListener('events-updated', e => {
      renderSecurityFindings(e.detail.events || []);
    });
  }
}

// Call after initial render
document.addEventListener('DOMContentLoaded', integrateSecurityFindingsHook);

// If your existing code fetches events like fetch('/api/events').then(r=>r.json()).then(ev=>{ ... })
// just add inside that .then block: renderSecurityFindings(ev);
