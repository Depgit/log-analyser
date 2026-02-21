/* ==================================================================
   SignalTrace — Wireshark Protocol Analyser — app.js
   ================================================================== */

const API = '';  // same origin
const PAGE_SIZE = 200;

let state = {
  sessionKey: null,
  allPackets: [],
  filteredPackets: [],
  currentProto: '',
  currentSearch: '',
  currentPage: 0,
  totalPackets: 0,
  selectedRow: null,
  currentView: 'packets',
  charts: {},
};

/* ── Boot ─────────────────────────────────────────────────────────── */
document.addEventListener('DOMContentLoaded', () => {
  setupDropzone();
  setupSearch();
  setupProtoFilters();
});

/* ── File handling ────────────────────────────────────────────────── */
function setupDropzone() {
  const dropzone = document.getElementById('dropzone');
  const fileInput = document.getElementById('fileInput');

  fileInput.addEventListener('change', e => {
    if (e.target.files[0]) uploadFile(e.target.files[0]);
  });

  dropzone.addEventListener('dragover', e => {
    e.preventDefault(); dropzone.classList.add('drag-over');
  });
  dropzone.addEventListener('dragleave', () => dropzone.classList.remove('drag-over'));
  dropzone.addEventListener('drop', e => {
    e.preventDefault(); dropzone.classList.remove('drag-over');
    const file = e.dataTransfer.files[0];
    if (file) uploadFile(file);
  });
}

async function uploadFile(file) {
  showProgress();
  const fd = new FormData();
  fd.append('file', file);
  try {
    const res = await fetch(`${API}/api/upload`, { method: 'POST', body: fd });
    const data = await res.json();
    if (!res.ok) {
      // Provide install steps if tshark is missing
      if (data.error && data.error.includes('tshark not found')) {
        showToast('⚠ tshark not installed — see console for install steps', true);
        console.error(
          '%c tshark is required to read .pcap/.pcapng files. ',
          'background:#ef4444;color:#fff;font-weight:bold;padding:2px 6px;border-radius:4px',
          '\n\nmacOS (Homebrew):\n  brew install wireshark\n\nUbuntu/Debian:\n  sudo apt install tshark\n\nAfter installing tshark, restart the server and try again.'
        );
      } else {
        showToast(data.error || 'Upload failed', true);
      }
      hideProgress();
      return;
    }
    state.sessionKey = data.session_key;
    state.totalPackets = data.packet_count;
    const fmt = data.format ? ` [${data.format.toUpperCase()}]` : '';
    document.getElementById('fileInfo').textContent =
      `${file.name}${fmt}  ·  ${data.packet_count.toLocaleString()} packets`;
    hideOverlay();
    await loadPackets();
    await loadStats();
  } catch (err) {
    showToast(err.message, true);
  }
  hideProgress();
}

function showProgress() {
  const inner = document.querySelector('.upload-inner');
  if (!inner.querySelector('.upload-progress')) {
    const bar = document.createElement('div');
    bar.className = 'upload-progress';
    bar.innerHTML = '<div class="upload-progress-bar"></div>';
    inner.appendChild(bar);
  }
}
function hideProgress() {
  document.querySelector('.upload-progress')?.remove();
}

function hideOverlay() {
  document.getElementById('uploadOverlay').classList.add('hidden');
  document.getElementById('appShell').classList.remove('hidden');
}

function newFile() {
  document.getElementById('appShell').classList.add('hidden');
  document.getElementById('uploadOverlay').classList.remove('hidden');
  document.getElementById('fileInput').value = '';
  document.getElementById('fileInfo').textContent = 'No file loaded';
  closeDetail();
  state.sessionKey = null;
  state.allPackets = [];
  state.filteredPackets = [];
  Object.values(state.charts).forEach(c => c?.destroy());
  state.charts = {};
}

/* ── View switching ───────────────────────────────────────────────── */
function switchView(view) {
  state.currentView = view;
  const views = ['packets', 'flows', 'unanswered', 'stats'];
  views.forEach(v => {
    document.getElementById(`view${cap(v)}Area`).classList.toggle('hidden', v !== view);
    document.getElementById(`view${cap(v)}`).classList.toggle('active', v === view);
  });
  if (view === 'flows') loadFlows();
  if (view === 'unanswered') loadUnanswered();
  if (view === 'stats') renderStats();
}
function cap(s) { return s.charAt(0).toUpperCase() + s.slice(1); }

/* ── Packet loading ───────────────────────────────────────────────── */
async function loadPackets(page = 0) {
  state.currentPage = page;
  const offset = page * PAGE_SIZE;
  const params = new URLSearchParams({
    limit: PAGE_SIZE,
    offset,
    session: state.sessionKey || '',
  });
  if (state.currentProto) params.set('proto', state.currentProto);
  if (state.currentSearch) params.set('search', state.currentSearch);

  try {
    const res = await fetch(`${API}/api/packets?${params}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    renderTable(data.packets, data.total, page);
    updateSidebar(data.total);
  } catch (err) {
    showToast(err.message, true);
  }
}

/* ── Table rendering ──────────────────────────────────────────────── */
function renderTable(packets, total, page) {
  const tbody = document.getElementById('packetBody');
  tbody.innerHTML = '';

  packets.forEach(pkt => {
    const tr = document.createElement('tr');
    tr.dataset.frame = pkt.frame_num;

    const info = pkt.info || buildInfoStr(pkt);
    const t = formatTime(pkt.time_rel || pkt.time_epoch);

    tr.innerHTML = `
      <td class="col-num">${pkt.frame_num}</td>
      <td class="col-time" title="${pkt.time_epoch || ''}">${t}</td>
      <td title="${pkt.src}">${pkt.src || '—'}</td>
      <td title="${pkt.dst}">${pkt.dst || '—'}</td>
      <td class="col-proto"><span class="proto-tag proto-${pkt.protocol}">${pkt.protocol?.toUpperCase()}</span></td>
      <td title="${info}">${info}</td>
      <td class="col-len" style="text-align:right">${pkt.length || ''}</td>
    `;
    tr.addEventListener('click', () => selectPacket(tr, pkt.frame_num));
    tbody.appendChild(tr);
  });

  // Packet count
  const proto = state.currentProto ? ` [${state.currentProto.toUpperCase()}]` : '';
  document.getElementById('packetCount').textContent =
    `${total.toLocaleString()} packets${proto}`;

  renderPagination(total, page);
}

function buildInfoStr(pkt) {
  const parts = [];
  if (pkt.tcap_type) parts.push(`TCAP: ${pkt.tcap_type}`);
  if (pkt.map_op) parts.push(`MAP: ${pkt.map_op}`);
  if (pkt.cap_op) parts.push(`CAP: ${pkt.cap_op}`);
  return parts.join(' | ') || '';
}

function formatTime(t) {
  if (!t) return '';
  const f = parseFloat(t);
  if (isNaN(f)) return t.slice(0, 10);
  return f.toFixed(6);
}

/* ── Pagination ───────────────────────────────────────────────────── */
function renderPagination(total, currentPage) {
  const totalPages = Math.ceil(total / PAGE_SIZE);
  const container = document.getElementById('pagination');
  container.innerHTML = '';
  if (totalPages <= 1) return;

  const info = document.createElement('span');
  info.className = 'page-info';
  info.textContent = `Page ${currentPage + 1} / ${totalPages}`;

  const prev = document.createElement('button');
  prev.className = 'page-btn'; prev.textContent = '←';
  prev.disabled = currentPage === 0;
  prev.onclick = () => loadPackets(currentPage - 1);

  const next = document.createElement('button');
  next.className = 'page-btn'; next.textContent = '→';
  next.disabled = currentPage >= totalPages - 1;
  next.onclick = () => loadPackets(currentPage + 1);

  container.append(prev, info, next);
}

/* ── Packet detail ────────────────────────────────────────────────── */
async function selectPacket(tr, frameNum) {
  // Highlight
  document.querySelectorAll('#packetBody tr').forEach(r => r.classList.remove('selected'));
  tr.classList.add('selected');
  state.selectedRow = frameNum;

  try {
    const res = await fetch(`${API}/api/packet/${frameNum}?session=${state.sessionKey || ''}`);
    const pkt = await res.json();
    renderDetail(pkt);
  } catch (err) {
    showToast('Failed to load packet detail', true);
  }
}

function renderDetail(pkt) {
  const drawer = document.getElementById('detailDrawer');
  drawer.classList.remove('hidden');
  document.getElementById('detailTitle').textContent = `Frame #${pkt.frame_num} — ${pkt.protocol?.toUpperCase()}`;

  const body = document.getElementById('detailBody');
  body.innerHTML = '';

  const sections = document.createElement('div');
  sections.className = 'detail-sections';

  // Frame info
  sections.appendChild(makeDetailSection('Frame', [
    ['Number', pkt.frame_num],
    ['Time (rel)', pkt.time_rel],
    ['Time (epoch)', pkt.time_epoch],
    ['Length', pkt.length + ' bytes'],
    ['Source', pkt.src],
    ['Destination', pkt.dst],
    ['Protocol', pkt.protocol],
  ]));

  // TCAP
  if (pkt.tcap) {
    sections.appendChild(makeDetailSection('TCAP', [
      ['Message Type', pkt.tcap.message_type],
      ['OTID', pkt.tcap.otid],
      ['DTID', pkt.tcap.dtid],
      ['App Context', pkt.tcap.app_context],
    ]));
  }

  // GSM_MAP
  if (pkt.gsm_map) {
    sections.appendChild(makeDetailSection('GSM_MAP', [
      ['Operation', `${pkt.gsm_map.op_name || ''} (${pkt.gsm_map.op_code || ''})`],
      ['Component', pkt.gsm_map.component],
      ['Invoke ID', pkt.gsm_map.invoke_id],
      ['IMSI', pkt.gsm_map.imsi],
      ['MSISDN', pkt.gsm_map.msisdn],
      ['Called GT', pkt.gsm_map.called_gt],
      ['Calling GT', pkt.gsm_map.calling_gt],
      ['Error Code', pkt.gsm_map.error_code],
    ].filter(r => r[1])));
  }

  // CAP
  if (pkt.cap) {
    sections.appendChild(makeDetailSection('CAP / SCP', [
      ['Operation', pkt.cap.operation],
      ['Service Key', pkt.cap.service_key],
      ['IMSI', pkt.cap.imsi],
      ['Called Number', pkt.cap.called_number],
      ['Calling Number', pkt.cap.calling_number],
      ['Event Type', pkt.cap.event_type],
    ].filter(r => r[1])));
  }

  body.appendChild(sections);

  // Protocol layers tree
  if (pkt.layers && Object.keys(pkt.layers).length) {
    const layerWrap = document.createElement('div');
    layerWrap.style.cssText = 'margin-top:12px';
    const layerTitle = document.createElement('div');
    layerTitle.className = 'detail-section-title';
    layerTitle.style.cssText = 'padding:0 0 6px; font-size:10px; color:var(--text-muted);';
    layerTitle.textContent = 'Protocol Layers';
    layerWrap.appendChild(layerTitle);
    const tree = renderLayerTree(pkt.layers);
    layerWrap.appendChild(tree);
    body.appendChild(layerWrap);
  }
}

function makeDetailSection(title, rows) {
  const sec = document.createElement('div');
  sec.className = 'detail-section';
  const t = document.createElement('div');
  t.className = 'detail-section-title'; t.textContent = title;
  sec.appendChild(t);
  rows.forEach(([k, v]) => {
    if (!v && v !== 0) return;
    const row = document.createElement('div');
    row.className = 'detail-row';
    row.innerHTML = `<span class="detail-key">${k}</span><span class="detail-val detail-val-highlight">${v}</span>`;
    sec.appendChild(row);
  });
  return sec;
}

function renderLayerTree(layers) {
  const wrap = document.createElement('div');
  wrap.className = 'field-tree';
  Object.entries(layers).forEach(([name, layer]) => {
    const header = document.createElement('div');
    header.style.cssText = 'color:var(--cyan);font-weight:600;padding:4px 0 2px;font-size:11px;cursor:pointer;';
    header.textContent = `▸ ${name}`;
    const fieldsDiv = document.createElement('div');
    fieldsDiv.style.cssText = 'padding-left:16px; display:none;';
    header.onclick = () => {
      const shown = fieldsDiv.style.display !== 'none';
      fieldsDiv.style.display = shown ? 'none' : 'block';
      header.textContent = (shown ? '▸ ' : '▾ ') + name;
    };
    (layer.fields || []).forEach(f => {
      const frow = document.createElement('div');
      frow.className = 'field-node';
      frow.innerHTML =
        `<span class="field-node-name">${f.name}</span>` +
        `<span class="field-node-sep">=</span>` +
        `<span class="field-node-val">${f.show || f.value || ''}</span>`;
      fieldsDiv.appendChild(frow);
    });
    wrap.appendChild(header);
    wrap.appendChild(fieldsDiv);
  });
  return wrap;
}

function closeDetail() {
  document.getElementById('detailDrawer').classList.add('hidden');
  document.querySelectorAll('#packetBody tr.selected')
    .forEach(r => r.classList.remove('selected'));
}

/* ── Protocol filters and search ─────────────────────────────────── */
function setupProtoFilters() {
  // Buttons are now generated and bound dynamically in renderProtoFilters()
}

function setupSearch() {
  const input = document.getElementById('searchInput');
  let debounce;
  input.addEventListener('input', () => {
    clearTimeout(debounce);
    debounce = setTimeout(() => {
      state.currentSearch = input.value.trim();
      state.currentPage = 0;
      closeDetail();
      loadPackets(0);
    }, 350);
  });
}

/* ── Sidebar summary ──────────────────────────────────────────────── */
function updateSidebar(filteredTotal) {
  const div = document.getElementById('sidebarSummary');
  div.innerHTML = `
    <div class="sidebar-title">Summary</div>
    <div class="stat-item">
      <span class="stat-item-label">Total</span>
      <span class="stat-item-val">${state.totalPackets.toLocaleString()}</span>
    </div>
    <div class="stat-item">
      <span class="stat-item-label">Shown</span>
      <span class="stat-item-val">${filteredTotal.toLocaleString()}</span>
    </div>
  `;
}

/* ── Flow diagrams ────────────────────────────────────────────────── */
async function loadFlows() {
  const container = document.getElementById('flowContainer');
  container.innerHTML = '<div style="color:var(--text-muted);padding:20px">Loading flows…</div>';
  try {
    const res = await fetch(`${API}/api/flows?session=${state.sessionKey || ''}`);
    const flows = await res.json();
    renderFlows(flows, container);
  } catch (err) {
    container.innerHTML = `<div style="color:var(--red);padding:20px">${err.message}</div>`;
  }
}

function renderFlows(flows, container) {
  container.innerHTML = '';
  if (!flows || flows.length === 0) {
    container.innerHTML = '<div style="color:var(--text-muted);padding:32px;text-align:center">No TCAP transactions found.<br><span style="font-size:11px">GSM_MAP/TCAP packets are needed for flow tracking.</span></div>';
    return;
  }

  // Sort flows by first message time
  flows.sort((a, b) => {
    const ta = parseFloat(a.messages?.[0]?.time_rel || 0);
    const tb = parseFloat(b.messages?.[0]?.time_rel || 0);
    return ta - tb;
  });

  flows.forEach(flow => {
    const card = document.createElement('div');
    card.className = 'flow-card';

    const header = document.createElement('div');
    header.className = 'flow-card-header';
    header.innerHTML = `
      <span style="font-size:10px;color:var(--text-muted);text-transform:uppercase;letter-spacing:.08em;">TCAP Flow</span>
      <span class="flow-tid">OTID: ${flow.otid}</span>
      ${flow.dtid ? `<span class="flow-arrow-label">→ DTID: ${flow.dtid}</span>` : ''}
      <span style="margin-left:auto;font-size:11px;color:var(--text-muted)">${flow.messages?.length || 0} messages</span>
    `;
    card.appendChild(header);

    const seq = document.createElement('div');
    seq.className = 'flow-seq';
    (flow.messages || []).forEach(msg => {
      const label = [msg.tcap_type, msg.map_op, msg.cap_op].filter(Boolean).join(' · ');
      const msgEl = document.createElement('div');
      msgEl.className = 'flow-msg';
      msgEl.innerHTML = `
        <div class="flow-msg-from" title="${msg.src}">${shortHost(msg.src)}</div>
        <div class="flow-msg-arrow">
          <div class="flow-msg-line"></div>
          <div class="flow-msg-label">${label || '—'}</div>
          <div class="flow-msg-arrowhead"></div>
        </div>
        <div class="flow-msg-to" title="${msg.dst}">${shortHost(msg.dst)}</div>
        <span class="flow-msg-time">${formatTime(msg.time_rel)}</span>
      `;
      // Click to jump to packet
      msgEl.style.cursor = 'pointer';
      msgEl.addEventListener('click', () => {
        switchView('packets');
        scrollToFrame(msg.frame_num);
      });
      seq.appendChild(msgEl);
    });
    card.appendChild(seq);
    container.appendChild(card);
  });
}

function shortHost(ip) {
  if (!ip) return '?';
  const parts = ip.split('.');
  if (parts.length === 4) return parts.slice(2).join('.'); // last 2 octets
  return ip.length > 15 ? ip.slice(-15) : ip;
}

function scrollToFrame(frameNum) {
  const tr = document.querySelector(`#packetBody tr[data-frame="${frameNum}"]`);
  if (tr) { tr.scrollIntoView({ block: 'center' }); selectPacket(tr, frameNum); }
}

/* ── Unanswered requests ──────────────────────────────────────────── */
async function loadUnanswered() {
  try {
    const res = await fetch(`${API}/api/unanswered?session=${state.sessionKey || ''}`);
    const data = await res.json();
    if (!res.ok) throw new Error(data.error);
    renderUnansweredTable(data || []);
  } catch (err) {
    showToast(err.message, true);
  }
}

function renderUnansweredTable(requests) {
  const tbody = document.getElementById('unansweredBody');
  tbody.innerHTML = '';

  if (!requests || requests.length === 0) {
    document.getElementById('unansweredCount').textContent = '0 unanswered requests';
    const tr = tbody.insertRow();
    tr.innerHTML = '<td colspan="9" style="text-align:center;color:var(--text-muted);padding:32px">All requests were answered</td>';
    return;
  }

  requests.forEach(req => {
    const tr = document.createElement('tr');
    tr.dataset.frame = req.frame_num;

    const statusClass = req.status === 'error_response' ? 'status-error' : 'status-missing';
    const statusLabel = req.status === 'error_response' ? '❌ Error' : '⏱ No Response';
    const respFrame = req.response_frame ? `${req.response_frame}` : '—';

    tr.innerHTML = `
      <td class="col-num">${req.frame_num}</td>
      <td class="col-time">${formatTime(req.time_rel)}</td>
      <td title="${req.src}">${req.src || '—'}</td>
      <td title="${req.dst}">${req.dst || '—'}</td>
      <td>${req.operation || '—'}</td>
      <td><span class="status-badge ${statusClass}">${statusLabel}</span></td>
      <td style="font-family:monospace;font-size:11px">${req.imsi || '—'}</td>
      <td style="font-family:monospace;font-size:11px">${req.msisdn || '—'}</td>
      <td class="col-len" style="text-align:right">${respFrame}</td>
    `;
    
    tr.addEventListener('click', () => selectPacket(tr, req.frame_num));
    tbody.appendChild(tr);
  });

  document.getElementById('unansweredCount').textContent = 
    `${requests.length} unanswered request${requests.length !== 1 ? 's' : ''}`;
}

/* ── Statistics charts ────────────────────────────────────────────── */
async function loadStats() {
  try {
    const res = await fetch(`${API}/api/stats?session=${state.sessionKey || ''}`);
    state.statsData = await res.json();
    renderProtoFilters(state.statsData.all_protocols_dist);
    if (state.currentView === 'stats') renderStats();
  } catch { }
}

function renderProtoFilters(dist) {
  if (!dist) return;
  const container = document.getElementById('protoFilters');
  container.innerHTML = `<button class="filter-btn ${state.currentProto === '' ? 'active' : ''}" data-proto="">All Packets</button>`;

  // Sort protocols descending by packet count
  const sorted = Object.entries(dist).sort((a, b) => b[1] - a[1]);

  sorted.forEach(([proto, count]) => {
    // Determine dot color by parsing out common known ones
    let dotClass = 'dot-default';
    const low = proto.toLowerCase();
    if (low === 'gsm_map') dotClass = 'dot-map';
    else if (low === 'cap') dotClass = 'dot-cap';
    else if (low === 'tcap') dotClass = 'dot-tcap';
    else if (low === 'sccp') dotClass = 'dot-sccp';
    else if (low === 'm3ua') dotClass = 'dot-m3ua';

    const btn = document.createElement('button');
    btn.className = `filter-btn ${state.currentProto === proto ? 'active' : ''}`;
    btn.dataset.proto = proto;
    btn.innerHTML = `<span class="dot ${dotClass}"></span>${proto.toUpperCase()} <span style="margin-left:auto;font-size:10px;opacity:0.5">${count}</span>`;

    btn.addEventListener('click', () => {
      document.querySelectorAll('.filter-btn[data-proto]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.currentProto = proto;
      state.currentPage = 0;
      closeDetail();
      loadPackets(0);
    });

    container.appendChild(btn);
  });
}

function renderStats() {
  const data = state.statsData;
  if (!data) return;

  renderChart('chartProto', 'doughnut', data.protocol_dist, 'Protocol Distribution');
  renderChart('chartTcap', 'doughnut', data.tcap_message_types, 'TCAP Types');
  renderBarChart('chartMap', topN(data.gsm_map_operations, 15));
  renderBarChart('chartCap', topN(data.cap_operations, 15));
}

function topN(obj, n) {
  if (!obj) return {};
  return Object.fromEntries(
    Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, n)
  );
}

const COLORS = [
  '#00d4ff', '#9b59b6', '#10b981', '#f59e0b', '#ef4444',
  '#3b82f6', '#fb923c', '#ec4899', '#84cc16', '#06b6d4',
  '#a78bfa', '#f97316', '#14b8a6', '#fbbf24', '#6366f1',
];

function renderChart(id, type, data, label) {
  if (!data || Object.keys(data).length === 0) return;
  const ctx = document.getElementById(id);
  if (!ctx) return;
  if (state.charts[id]) { state.charts[id].destroy(); }

  state.charts[id] = new Chart(ctx, {
    type,
    data: {
      labels: Object.keys(data),
      datasets: [{
        data: Object.values(data),
        backgroundColor: COLORS,
        borderColor: 'rgba(0,0,0,0.3)',
        borderWidth: 1,
      }],
    },
    options: {
      responsive: true, maintainAspectRatio: false,
      plugins: {
        legend: {
          labels: { color: '#94a3b8', font: { family: 'Inter', size: 11 }, boxWidth: 12 },
        },
      },
    },
  });
}

function renderBarChart(id, data) {
  if (!data || Object.keys(data).length === 0) return;
  const ctx = document.getElementById(id);
  if (!ctx) return;
  if (state.charts[id]) { state.charts[id].destroy(); }

  state.charts[id] = new Chart(ctx, {
    type: 'bar',
    data: {
      labels: Object.keys(data),
      datasets: [{
        data: Object.values(data),
        backgroundColor: COLORS[0],
        borderRadius: 4,
      }],
    },
    options: {
      indexAxis: 'y',
      responsive: true, maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: '#64748b', font: { size: 10 } }, grid: { color: 'rgba(255,255,255,0.04)' } },
        y: { ticks: { color: '#94a3b8', font: { family: 'JetBrains Mono', size: 10 } }, grid: { display: false } },
      },
    },
  });
}

/* ── CSV Export ───────────────────────────────────────────────────── */
function exportCSV() {
  const rows = [['Frame', 'Time', 'Source', 'Destination', 'Protocol', 'Length', 'Info']];
  document.querySelectorAll('#packetBody tr').forEach(tr => {
    const tds = tr.querySelectorAll('td');
    if (tds.length >= 7) {
      rows.push([
        tds[0].textContent.trim(),
        tds[1].textContent.trim(),
        tds[2].textContent.trim(),
        tds[3].textContent.trim(),
        tds[4].textContent.trim(),
        tds[6].textContent.trim(),
        tds[5].title || tds[5].textContent.trim(),
      ]);
    }
  });
  const csv = rows.map(r => r.map(c => `"${c.replace(/"/g, '""')}"`).join(',')).join('\n');
  const blob = new Blob([csv], { type: 'text/csv' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a'); a.href = url; a.download = 'packets.csv'; a.click();
  setTimeout(() => URL.revokeObjectURL(url), 500);
  showToast('CSV exported!');
}

/* ── Toast ────────────────────────────────────────────────────────── */
let toastTimer;
function showToast(msg, isError = false) {
  const el = document.getElementById('toast');
  el.textContent = msg;
  el.classList.toggle('error', isError);
  el.classList.add('visible');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.remove('visible'), 3000);
}
