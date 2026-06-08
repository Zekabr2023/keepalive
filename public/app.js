/* ─────────────────────────────────────────────────────────────────
   Anti-Pausa Supabase — Frontend Logic
   ───────────────────────────────────────────────────────────────── */

const API = '';  // same origin
let projects  = [];
let setupProjectId = null;
let currentSection = 'dashboard';
let countdownInterval = null;

// ─── Auth ─────────────────────────────────────────────────────────
let authToken = localStorage.getItem('antipausa_token') || '';

function apiHeaders(extra = {}) {
  return {
    'Content-Type': 'application/json',
    ...(authToken ? { 'Authorization': `Bearer ${authToken}` } : {}),
    ...extra
  };
}

async function apiFetch(url, opts = {}) {
  const res = await fetch(url, {
    ...opts,
    headers: { ...(opts.headers || {}), ...(authToken ? { 'Authorization': `Bearer ${authToken}` } : {}) }
  });
  if (res.status === 401) {
    const data = await res.json().catch(() => ({}));
    if (data.requireAuth) { showLogin(); throw new Error('Sessão expirada'); }
  }
  return res;
}

function showLogin() {
  document.getElementById('loginOverlay').style.display = 'flex';
  document.querySelector('.app').style.display = 'none';
}

function hideLogin() {
  document.getElementById('loginOverlay').style.display = 'none';
  document.querySelector('.app').style.display = '';
}

async function handleLogin(event) {
  if (event) event.preventDefault();
  const pw  = document.getElementById('loginPassword').value;
  const err = document.getElementById('loginError');
  const btn = document.getElementById('loginBtn');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Entrando...';
  err.style.display = 'none';

  try {
    const res  = await fetch(`${API}/api/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ password: pw })
    });
    const data = await res.json();

    if (data.success) {
      authToken = data.token || '';
      if (authToken) localStorage.setItem('antipausa_token', authToken);
      hideLogin();
      loadDashboard();
    } else {
      err.textContent = data.error || 'Senha incorreta';
      err.style.display = '';
    }
  } catch (e) {
    err.textContent = 'Erro de conexão';
    err.style.display = '';
  } finally {
    btn.disabled = false;
    btn.innerHTML = 'Entrar';
  }
}

async function logout() {
  if (authToken) {
    await fetch(`${API}/api/auth/logout`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${authToken}` }
    }).catch(() => {});
  }
  authToken = '';
  localStorage.removeItem('antipausa_token');
  showLogin();
}

// ─── Init ─────────────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', async () => {
  // Check auth status first
  try {
    const res  = await fetch(`${API}/api/auth/check`,
      authToken ? { headers: { 'Authorization': `Bearer ${authToken}` } } : {}
    );
    const data = await res.json();

    if (data.passwordRequired && !data.authenticated) {
      showLogin();
      return;
    }
    if (!data.passwordRequired) authToken = ''; // sem senha: limpa token
  } catch {
    // Se falhar (offline?), tenta de qualquer forma
  }

  hideLogin();
  loadDashboard();
  setInterval(loadDashboard, 30_000);
  setInterval(updateCountdown, 1000);
  setInterval(loadSideStats, 10_000);
  loadSideStats();
});


// ─── Navigation ───────────────────────────────────────────────────
function showSection(name) {
  currentSection = name;
  document.getElementById('sectionDashboard').style.display = name === 'dashboard' ? '' : 'none';
  document.getElementById('sectionLogs').style.display      = name === 'logs'      ? '' : 'none';
  document.getElementById('sectionTitle').textContent       = name === 'dashboard' ? 'Dashboard' : 'Logs de Atividade';
  document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('nav-item--active'));
  event?.currentTarget?.classList.add('nav-item--active');
  if (name === 'logs') loadLogs();
}

// ─── Dashboard ────────────────────────────────────────────────────
async function loadDashboard() {
  try {
    const [projRes, statusRes] = await Promise.all([
      fetch(`${API}/api/projects`),
      fetch(`${API}/api/status`)
    ]);
    projects = await projRes.json();
    const status = await statusRes.json();
    renderSummary(status);
    renderProjects();
    updateSideStats(status);
  } catch (err) {
    console.error('Erro ao carregar dashboard:', err);
  }
}

function renderSummary(status) {
  setText('sumActive', status.active  ?? 0);
  setText('sumSetup',  status.setupReq ?? 0);
  setText('sumPaused', status.paused  ?? 0);
  setText('sumTotal',  status.total   ?? 0);
}

function renderProjects() {
  const grid = document.getElementById('projectsGrid');
  const empty = document.getElementById('emptyState');

  if (!projects || projects.length === 0) {
    grid.innerHTML = '';
    grid.appendChild(empty);
    empty.style.display = '';
    return;
  }

  // Remove empty state
  if (empty.parentNode === grid) grid.removeChild(empty);

  // Remove cards for deleted projects
  grid.querySelectorAll('.project-card').forEach(card => {
    if (!projects.find(p => p.id === card.dataset.id)) card.remove();
  });

  // Add/update cards
  projects.forEach((p, i) => {
    let card = grid.querySelector(`[data-id="${p.id}"]`);
    const html = buildCardHTML(p);
    if (!card) {
      card = document.createElement('div');
      card.dataset.id = p.id;
      card.style.animationDelay = `${i * 40}ms`;
      grid.appendChild(card);
    }
    card.outerHTML; // prevent re-render if same
    card = grid.querySelector(`[data-id="${p.id}"]`) || card;
    card.className = `project-card project-card--${p.enabled === false ? 'disabled' : (p.status || 'checking')}`;
    card.dataset.id = p.id;
    card.innerHTML = html;
  });
}

function buildCardHTML(p) {
  const statusLabel = {
    active:         '● Ativo',
    setup_required: '● Setup Necessário',
    paused:         '● Pausado',
    error:          '● Erro',
    checking:       '● Verificando...',
    disabled:       '● Desativado'
  };

  const effectiveStatus = p.enabled === false ? 'disabled' : (p.status || 'checking');
  const badge = statusLabel[effectiveStatus] || effectiveStatus;

  const lastPingStr = p.lastPing
    ? `${relativeTime(p.lastPing)}`
    : 'Nunca';

  const nextPingStr = p.lastPing && p.enabled && p.status === 'active'
    ? nextPingCountdown(p.lastPing)
    : '—';

  const hasError = p.lastError && p.status !== 'active';

  return `
    <div class="card-top">
      <div>
        <div class="card-name">${escapeHTML(p.name)}</div>
        ${p.projectRef ? `<div class="card-ref">${p.projectRef}</div>` : ''}
      </div>
      <span class="status-badge status-badge--${effectiveStatus}">${badge}</span>
    </div>

    <div class="card-stats">
      <div class="card-stat">
        <div class="card-stat-label">Último ping</div>
        <div class="card-stat-value card-stat-value--${p.lastPing ? 'green' : ''}">${lastPingStr}</div>
      </div>
      <div class="card-stat">
        <div class="card-stat-label">Total de pings</div>
        <div class="card-stat-value">${p.pingCount || 0}</div>
      </div>
      <div class="card-stat" style="grid-column:1/-1">
        <div class="card-stat-label">Próximo ping</div>
        <div class="card-stat-value card-stat-value--${p.status === 'active' ? 'yellow' : ''}"
             id="nextPing-${p.id}">${nextPingStr}</div>
      </div>
    </div>

    ${p.status === 'active' && p.lastPing ? `
    <div class="ping-progress">
      <div class="ping-progress-fill" id="progress-${p.id}" style="width:${pingProgressPct(p.lastPing)}%"></div>
    </div>` : ''}

    ${hasError ? `<div class="card-error">⚠ ${escapeHTML(p.lastError)}</div>` : ''}

    <div class="card-actions">
      ${(p.status === 'active' || p.status === 'error' || p.status === 'checking') ? `
        <button class="btn btn--ghost btn--sm" onclick="manualPing('${p.id}')" id="pingBtn-${p.id}">
          ⚡ Ping
        </button>` : ''}
      ${p.status === 'setup_required' ? `
        <button class="btn btn--ghost btn--sm" onclick="manualPing('${p.id}')" id="pingBtn-${p.id}">
          ⚡ Forçar Ping
        </button>
        <button class="btn btn--yellow btn--sm" onclick="openSetupModal('${p.id}')">
          ⚙️ Configurar Tabela
        </button>` : ''}
      ${p.status === 'paused' ? `
        <button class="btn btn--outline btn--sm" onclick="refreshProject('${p.id}')">
          🔄 Verificar Status
        </button>` : ''}
      <button class="btn btn--ghost btn--sm" onclick="toggleProject('${p.id}', ${p.enabled !== false})">
        ${p.enabled !== false ? '⏸ Pausar' : '▶ Ativar'}
      </button>
      <button class="btn btn--danger btn--sm" onclick="deleteProject('${p.id}', '${escapeHTML(p.name)}')">
        🗑
      </button>
    </div>
  `;
}

// ─── Sidebar Stats ────────────────────────────────────────────────
async function loadSideStats() {
  try {
    const res    = await fetch(`${API}/api/status`);
    const status = await res.json();
    updateSideStats(status);
  } catch {}
}

function updateSideStats(status) {
  setText('sideStatActive', `${status.active ?? 0} / ${status.total ?? 0}`);
  const totalPings = projects.reduce((s, p) => s + (p.pingCount || 0), 0);
  setText('sideStatPings', totalPings);
  setText('sideStatUptime', formatUptime(status.uptime || 0));

  if (status.nextPingMs !== null && status.nextPingMs !== undefined) {
    window._nextPingMs = status.nextPingMs;
    window._nextPingLoaded = Date.now();
  }
}

function updateCountdown() {
  const el = document.getElementById('nextPingCountdown');
  if (!el) return;

  if (window._nextPingMs === undefined || window._nextPingMs === null) {
    el.textContent = '—';
    return;
  }

  const elapsed = Date.now() - (window._nextPingLoaded || Date.now());
  const remaining = Math.max(0, window._nextPingMs - elapsed);

  el.textContent = formatDuration(remaining);

  // Update all per-project countdowns
  projects.forEach(p => {
    if (p.lastPing && p.status === 'active' && p.enabled !== false) {
      const nextEl = document.getElementById(`nextPing-${p.id}`);
      if (nextEl) nextEl.textContent = nextPingCountdown(p.lastPing);
      const progEl = document.getElementById(`progress-${p.id}`);
      if (progEl) progEl.style.width = `${pingProgressPct(p.lastPing)}%`;
    }
  });
}

// ─── Actions ──────────────────────────────────────────────────────
async function manualPing(id) {
  const btn = document.getElementById(`pingBtn-${id}`);
  const card = document.querySelector(`[data-id="${id}"]`);
  if (btn) { btn.disabled = true; btn.textContent = '⏳ Pingando...'; }
  if (card) card.classList.add('pinging');

  try {
    const res  = await fetch(`${API}/api/projects/${id}/ping`, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      toast('Ping realizado com sucesso! ✅', 'success');
      await loadDashboard();
    } else {
      toast(`Ping falhou: ${data.error}`, 'error');
    }
  } catch (err) {
    toast(`Erro: ${err.message}`, 'error');
  } finally {
    if (card) card.classList.remove('pinging');
  }
}

async function toggleProject(id, currentEnabled) {
  try {
    await fetch(`${API}/api/projects/${id}`, {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ enabled: !currentEnabled })
    });
    toast(currentEnabled ? 'Projeto pausado' : 'Projeto ativado', 'info');
    await loadDashboard();
  } catch (err) {
    toast(`Erro: ${err.message}`, 'error');
  }
}

async function deleteProject(id, name) {
  if (!confirm(`Remover o projeto "${name}"? Esta ação não pode ser desfeita.`)) return;
  try {
    await fetch(`${API}/api/projects/${id}`, { method: 'DELETE' });
    toast(`Projeto "${name}" removido`, 'info');
    await loadDashboard();
  } catch (err) {
    toast(`Erro: ${err.message}`, 'error');
  }
}

async function refreshProject(id) {
  try {
    const res  = await fetch(`${API}/api/projects/${id}/refresh`, { method: 'POST' });
    const data = await res.json();
    toast(`Status atualizado: ${data.status}`, data.connected ? 'success' : 'warning');
    await loadDashboard();
  } catch (err) {
    toast(`Erro: ${err.message}`, 'error');
  }
}

async function refreshAll() {
  const btn = document.getElementById('btnRefresh');
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Atualizando...'; }
  await loadDashboard();
  if (btn) { btn.disabled = false; btn.innerHTML = '<span>🔄</span> Atualizar'; }
  toast('Dashboard atualizado', 'success');
}

async function pingAll() {
  const btn = document.getElementById('btnPingAll');
  if (btn) { btn.disabled = true; btn.innerHTML = '<span class="spinner"></span> Pingando...'; }

  try {
    const res  = await fetch(`${API}/api/ping-all`, { method: 'POST' });
    const data = await res.json();
    if (data.started) {
      toast(`Pingando ${data.count} projeto(s) em background... aguarde 🚀`, 'info');
      // Atualiza o dashboard após alguns segundos
      setTimeout(loadDashboard, 8000);
      setTimeout(loadDashboard, 20000);
    } else {
      toast('Nenhum projeto ativo para pingar', 'warning');
    }
  } catch (err) {
    toast(`Erro: ${err.message}`, 'error');
  } finally {
    setTimeout(() => {
      if (btn) { btn.disabled = false; btn.innerHTML = '<span>⚡</span> Pingar Todos'; }
    }, 5000);
  }
}

// ─── PAT Import Modal ─────────────────────────────────────────────
let discoveredProjects = [];
let currentPAT = '';

function openPatModal() {
  document.getElementById('patModal').style.display = 'flex';
  document.getElementById('patStep1').style.display = '';
  document.getElementById('patStep2').style.display = 'none';
  document.getElementById('pat-input').value = '';
  document.getElementById('patDiscoverResult').style.display = 'none';
}

function closePatModal() {
  document.getElementById('patModal').style.display = 'none';
  discoveredProjects = [];
  currentPAT = '';
}

function backToPatStep1() {
  document.getElementById('patStep1').style.display = '';
  document.getElementById('patStep2').style.display = 'none';
}

async function discoverProjects() {
  const pat = document.getElementById('pat-input').value.trim();
  if (!pat) { toast('Cole o Personal Access Token primeiro', 'warning'); return; }

  const btn    = document.getElementById('btnDiscover');
  const result = document.getElementById('patDiscoverResult');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Consultando Supabase...';
  result.style.display = 'none';

  try {
    const res  = await fetch(`${API}/api/discover`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pat })
    });
    const data = await res.json();

    if (!res.ok) {
      result.className = 'test-result test-result--error';
      result.innerHTML = `❌ ${escapeHTML(data.error)}`;
      result.style.display = '';
      return;
    }

    currentPAT = pat;
    discoveredProjects = data.projects;

    // Move to step 2
    document.getElementById('patStep1').style.display = 'none';
    document.getElementById('patStep2').style.display = '';

    const newCount = data.projects.filter(p => !p.alreadyAdded).length;
    const existCount = data.projects.filter(p => p.alreadyAdded).length;
    document.getElementById('discoverSummary').innerHTML =
      `<strong>${data.count}</strong> projeto(s) encontrado(s) • <span style="color:var(--green)">${newCount} novo(s)</span>${existCount ? ` • <span style="color:var(--text-3)">${existCount} já adicionado(s)</span>` : ''}`;

    renderDiscoverList();

  } catch (err) {
    result.className = 'test-result test-result--error';
    result.innerHTML = `❌ Erro: ${escapeHTML(err.message)}`;
    result.style.display = '';
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>🔍</span> Descobrir Meus Projetos';
  }
}

function renderDiscoverList() {
  const list = document.getElementById('discoverList');
  const statusLabel = {
    ACTIVE_HEALTHY: { text: '● Ativo', cls: 'status-badge--active' },
    INACTIVE:       { text: '● Inativo', cls: 'status-badge--paused' },
    PAUSED_ACTIVE:  { text: '● Pausado', cls: 'status-badge--paused' }
  };

  list.innerHTML = discoveredProjects.map((p, i) => {
    const st = statusLabel[p.status] || { text: p.status, cls: '' };
    return `
      <div class="discover-item ${p.alreadyAdded ? 'already-added' : ''}"
           id="disc-${i}"
           onclick="${p.alreadyAdded ? '' : `toggleDiscoverItem(${i})`}">
        <div class="discover-check" id="discCheck-${i}"></div>
        <div class="discover-item-info">
          <div class="discover-item-name">${escapeHTML(p.name)}</div>
          <div class="discover-item-meta">
            <span>${p.ref}</span>
            <span>${p.region || ''}</span>
          </div>
        </div>
        <div class="discover-item-badges">
          <span class="status-badge ${st.cls}">${st.text}</span>
          ${p.alreadyAdded ? '<span class="status-badge status-badge--disabled">Já adicionado</span>' : ''}
          ${p.hasAnonKey ? '<span style="font-size:0.7rem;color:var(--green)">🔑</span>' : '<span style="font-size:0.7rem;color:var(--red)">⚠ sem key</span>'}
        </div>
      </div>`;
  }).join('');
}

function toggleDiscoverItem(idx) {
  const item  = document.getElementById(`disc-${idx}`);
  const check = document.getElementById(`discCheck-${idx}`);
  item.classList.toggle('selected');
  check.textContent = item.classList.contains('selected') ? '✓' : '';
  updateImportButton();
}

function selectAllProjects() {
  const btn = document.getElementById('btnSelectAll');
  const allSelected = discoveredProjects
    .filter(p => !p.alreadyAdded)
    .every((_, i) => {
      const realIdx = discoveredProjects.findIndex((p, j) => !p.alreadyAdded && j >= i);
      return document.getElementById(`disc-${realIdx}`)?.classList.contains('selected');
    });

  discoveredProjects.forEach((p, i) => {
    if (p.alreadyAdded) return;
    const item  = document.getElementById(`disc-${i}`);
    const check = document.getElementById(`discCheck-${i}`);
    if (!allSelected) {
      item.classList.add('selected');
      check.textContent = '✓';
    } else {
      item.classList.remove('selected');
      check.textContent = '';
    }
  });
  btn.textContent = allSelected ? 'Selecionar todos' : 'Desmarcar todos';
  updateImportButton();
}

function updateImportButton() {
  const selected = document.querySelectorAll('.discover-item.selected').length;
  const btn = document.getElementById('btnImport');
  btn.innerHTML = `<span>🚀</span> Importar ${selected} Projeto(s)`;
  btn.disabled = selected === 0;
}

async function importSelected() {
  const selectedRefs = discoveredProjects
    .filter((p, i) => !p.alreadyAdded && document.getElementById(`disc-${i}`)?.classList.contains('selected'))
    .map(p => p.ref);

  if (!selectedRefs.length) { toast('Selecione pelo menos um projeto', 'warning'); return; }

  const btn = document.getElementById('btnImport');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Importando...';

  try {
    const res  = await fetch(`${API}/api/import`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pat: currentPAT, refs: selectedRefs })
    });
    const data = await res.json();

    if (data.imported > 0) {
      toast(`${data.imported} projeto(s) importado(s) com sucesso! ✅`, 'success');
      closePatModal();
      await loadDashboard();
    } else {
      const errors = data.results?.filter(r => r.status === 'error').map(r => r.reason).join(', ');
      toast(`Nenhum projeto importado. ${errors || ''}`, 'error');
    }
  } catch (err) {
    toast(`Erro: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>🚀</span> Importar Selecionados';
  }
}

// ─── Add Project Modal ────────────────────────────────────────────
function openAddModal() {
  document.getElementById('addModal').style.display = 'flex';
  document.getElementById('addProjectForm').reset();
  document.getElementById('testResult').style.display = 'none';
}

function closeAddModal() {
  document.getElementById('addModal').style.display = 'none';
}

async function testConnectionForm() {
  const url      = document.getElementById('proj-url').value.trim();
  const anonKey  = document.getElementById('proj-anon').value.trim();
  const serviceKey = document.getElementById('proj-service').value.trim();
  const resultEl = document.getElementById('testResult');
  const btn      = document.getElementById('btnTest');

  if (!url || !anonKey) {
    showTestResult('error', '⚠ Preencha a URL e a Anon Key primeiro.');
    return;
  }

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Testando...';
  resultEl.style.display = 'none';

  try {
    const res  = await fetch(`${API}/api/projects/test`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ url, anonKey, serviceRoleKey: serviceKey || undefined })
    });
    const data = await res.json();

    if (data.connected && data.tableExists) {
      showTestResult('success', `✅ Conexão OK! Tabela <code>_revisoes</code> encontrada. Projeto pronto para uso.${data.projectRef ? ` • Ref: <code>${data.projectRef}</code>` : ''}`);
    } else if (data.connected && !data.tableExists) {
      showTestResult('warning', `⚠️ Conexão OK! Mas a tabela <code>_revisoes</code> não existe ainda. Após adicionar, clique em <strong>"Configurar Tabela"</strong> no card do projeto.${data.projectRef ? ` • Ref: <code>${data.projectRef}</code>` : ''}`);
    } else if (data.status === 'paused') {
      showTestResult('error', `⛔ Projeto pausado pelo Supabase. Você pode adicionar mesmo assim para monitorar.`);
    } else {
      showTestResult('error', `❌ Falha na conexão: ${data.error || 'Erro desconhecido'}. Verifique a URL e a Anon Key.`);
    }
  } catch (err) {
    showTestResult('error', `❌ Erro: ${err.message}`);
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>🔍</span> Testar Conexão';
  }
}

function showTestResult(type, html) {
  const el = document.getElementById('testResult');
  el.className = `test-result test-result--${type}`;
  el.innerHTML = html;
  el.style.display = '';
}

async function handleAddProject(event) {
  event.preventDefault();
  const name       = document.getElementById('proj-name').value.trim();
  const url        = document.getElementById('proj-url').value.trim();
  const anonKey    = document.getElementById('proj-anon').value.trim();
  const serviceKey = document.getElementById('proj-service').value.trim();
  const pat        = document.getElementById('proj-pat').value.trim();
  const btn        = document.getElementById('btnAdd');

  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Adicionando...';

  try {
    const res  = await fetch(`${API}/api/projects`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        name, url,
        anonKey,
        serviceRoleKey:       serviceKey || undefined,
        personalAccessToken:  pat || undefined
      })
    });
    const data = await res.json();

    if (res.ok) {
      toast(`Projeto "${name}" adicionado com sucesso!`, 'success');
      closeAddModal();
      await loadDashboard();
    } else {
      toast(`Erro: ${data.error}`, 'error');
    }
  } catch (err) {
    toast(`Erro: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>➕</span> Adicionar Projeto';
  }
}

// ─── Setup Modal ──────────────────────────────────────────────────
async function openSetupModal(projectId) {
  setupProjectId = projectId;
  const modal = document.getElementById('setupModal');
  modal.style.display = 'flex';

  const project = projects.find(p => p.id === projectId);
  if (project) {
    document.getElementById('setupModalSubtitle').textContent =
      `Projeto: ${project.name}`;
  }

  // Check if PAT is set
  const autoSection   = document.getElementById('setupAutoSection');
  const manualSection = document.getElementById('setupManualSection');

  document.getElementById('setupSQLContent').textContent = 'Carregando...';

  try {
    const res  = await fetch(`${API}/api/projects/${projectId}/setup`, { method: 'POST' });
    const data = await res.json();

    if (data.success && data.autoCreated) {
      toast('Tabela criada automaticamente! ✅', 'success');
      closeSetupModal();
      await loadDashboard();
      return;
    }

    if (data.requiresManualSetup || data.sql) {
      autoSection.style.display   = 'none';
      manualSection.style.display = '';
      document.getElementById('setupSQLContent').textContent = data.sql || '';
    } else {
      // Has PAT — show auto button
      autoSection.style.display   = '';
      manualSection.style.display = '';
      document.getElementById('setupSQLContent').textContent = data.sql || '';
    }
  } catch (err) {
    document.getElementById('setupSQLContent').textContent = '-- Erro ao carregar SQL: ' + err.message;
  }
}

function closeSetupModal() {
  document.getElementById('setupModal').style.display = 'none';
  setupProjectId = null;
}

async function autoCreateTable() {
  const btn = document.getElementById('btnAutoCreate');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Criando tabela...';

  try {
    const res  = await fetch(`${API}/api/projects/${setupProjectId}/setup`, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      toast('Tabela criada com sucesso! ✅', 'success');
      closeSetupModal();
      await loadDashboard();
    } else {
      toast(`Erro: ${data.error}`, 'error');
    }
  } catch (err) {
    toast(`Erro: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>🚀</span> Criar Tabela Automaticamente';
  }
}

async function confirmSetup() {
  const btn = document.getElementById('btnConfirmSetup');
  btn.disabled = true;
  btn.innerHTML = '<span class="spinner"></span> Verificando...';

  try {
    const res  = await fetch(`${API}/api/projects/${setupProjectId}/confirm-setup`, { method: 'POST' });
    const data = await res.json();
    if (data.success) {
      toast('Configuração confirmada! Projeto ativo. ✅', 'success');
      closeSetupModal();
      await loadDashboard();
    } else {
      toast(`Tabela não encontrada: ${data.error}`, 'error');
    }
  } catch (err) {
    toast(`Erro: ${err.message}`, 'error');
  } finally {
    btn.disabled = false;
    btn.innerHTML = '<span>✅</span> Já executei o SQL!';
  }
}

function copySQLToClipboard() {
  const sql = document.getElementById('setupSQLContent').textContent;
  navigator.clipboard.writeText(sql).then(() => {
    const btn = document.getElementById('btnCopySQL');
    btn.innerHTML = '<span>✅</span> Copiado!';
    setTimeout(() => { btn.innerHTML = '<span>📋</span> Copiar'; }, 2000);
  }).catch(() => toast('Não foi possível copiar', 'error'));
}

// ─── Logs ─────────────────────────────────────────────────────────
async function loadLogs() {
  const container = document.getElementById('logsContainer');
  const filter    = document.getElementById('logFilter')?.value || '';
  if (!container) return;

  container.innerHTML = '<div class="loading">Carregando logs...</div>';

  // Update filter select options
  const select = document.getElementById('logFilter');
  if (select && projects.length) {
    const currentVal = select.value;
    select.innerHTML = '<option value="">Todos os projetos</option>' +
      projects.map(p => `<option value="${p.id}" ${p.id === currentVal ? 'selected' : ''}>${escapeHTML(p.name)}</option>`).join('');
  }

  try {
    const url  = `${API}/api/logs?limit=100${filter ? `&projectId=${filter}` : ''}`;
    const res  = await fetch(url);
    const logs = await res.json();

    if (!logs.length) {
      container.innerHTML = '<div class="loading">Nenhum log encontrado</div>';
      return;
    }

    container.innerHTML = logs.map(log => {
      const proj = projects.find(p => p.id === log.projectId);
      return `
        <div class="log-entry">
          <div class="log-dot log-dot--${log.status}"></div>
          <div class="log-content">
            <div class="log-message">${escapeHTML(log.message)}</div>
            <div class="log-meta">
              <span class="log-time">${formatDateTime(log.timestamp)}</span>
              ${proj ? `<span class="log-project">${escapeHTML(proj.name)}</span>` : ''}
            </div>
          </div>
        </div>`;
    }).join('');
  } catch (err) {
    container.innerHTML = `<div class="loading">Erro: ${err.message}</div>`;
  }
}

// ─── Utilities ────────────────────────────────────────────────────
function toggleVisibility(inputId, btn) {
  const input = document.getElementById(inputId);
  if (input.type === 'password') {
    input.type = 'text';
    btn.textContent = '🙈';
  } else {
    input.type = 'password';
    btn.textContent = '👁';
  }
}

function setText(id, val) {
  const el = document.getElementById(id);
  if (el) el.textContent = val;
}

function escapeHTML(str) {
  if (!str) return '';
  return String(str).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function relativeTime(iso) {
  const diff = Date.now() - new Date(iso).getTime();
  const mins  = Math.floor(diff / 60000);
  const hours = Math.floor(diff / 3600000);
  const days  = Math.floor(diff / 86400000);
  if (mins  < 1)   return 'agora';
  if (mins  < 60)  return `${mins}m atrás`;
  if (hours < 24)  return `${hours}h atrás`;
  return `${days}d atrás`;
}

function nextPingCountdown(lastPingISO) {
  const next     = new Date(lastPingISO).getTime() + 47 * 3600 * 1000;
  const remaining = next - Date.now();
  if (remaining <= 0) return '⚡ Em breve';
  return formatDuration(remaining);
}

function pingProgressPct(lastPingISO) {
  const elapsed  = Date.now() - new Date(lastPingISO).getTime();
  const total    = 47 * 3600 * 1000;
  return Math.min(100, Math.round((elapsed / total) * 100));
}

function formatDuration(ms) {
  if (ms <= 0) return '00:00:00';
  const h = Math.floor(ms / 3600000);
  const m = Math.floor((ms % 3600000) / 60000);
  const s = Math.floor((ms % 60000) / 1000);
  return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}`;
}

function formatUptime(seconds) {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function formatDateTime(iso) {
  const d = new Date(iso);
  return d.toLocaleString('pt-BR', { day:'2-digit', month:'2-digit', hour:'2-digit', minute:'2-digit', second:'2-digit' });
}

// ─── Toast ────────────────────────────────────────────────────────
function toast(message, type = 'info') {
  const container = document.getElementById('toastContainer');
  const el = document.createElement('div');
  el.className = `toast toast--${type}`;
  el.innerHTML = `
    <span>${type === 'success' ? '✅' : type === 'error' ? '❌' : type === 'warning' ? '⚠️' : 'ℹ️'}</span>
    <span>${escapeHTML(message)}</span>
  `;
  container.appendChild(el);
  setTimeout(() => {
    el.classList.add('hiding');
    setTimeout(() => el.remove(), 250);
  }, 3500);
}

// ─── Close modals on overlay click ────────────────────────────────
document.getElementById('addModal').addEventListener('click', e => {
  if (e.target === e.currentTarget) closeAddModal();
});
document.getElementById('setupModal').addEventListener('click', e => {
  if (e.target === e.currentTarget) closeSetupModal();
});
document.getElementById('patModal').addEventListener('click', e => {
  if (e.target === e.currentTarget) closePatModal();
});
