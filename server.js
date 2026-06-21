const express = require('express');
const cors    = require('cors');
const cron    = require('node-cron');
const path    = require('path');
const fs      = require('fs');
const crypto  = require('crypto');

const app  = express();
const PORT = process.env.PORT || 3131;

// ─── Security Headers ──────────────────────────────────────────────────────────────
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.setHeader('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://fonts.googleapis.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com https://fonts.gstatic.com; font-src https://fonts.gstatic.com; img-src 'self' data:; connect-src 'self'");
  next();
});

app.use(cors({ origin: false })); // sem CORS público
app.use(express.json({ limit: '50kb' })); // limita payload
app.use(express.static(path.join(__dirname, 'public')));

// ─── Encryption (AES-256-GCM) ───────────────────────────────────────────────────────
const KEY_FILE = path.join(__dirname, 'data', '.enc_key');
let ENC_KEY;  // Buffer de 32 bytes

function initEncryptionKey() {
  const envKey = process.env.ENCRYPTION_KEY;
  if (envKey && envKey.length === 64) {
    ENC_KEY = Buffer.from(envKey, 'hex');
    return;
  }
  // Gera e persiste uma chave aleatória se não configurada
  if (!fs.existsSync(path.dirname(KEY_FILE))) fs.mkdirSync(path.dirname(KEY_FILE), { recursive: true });
  if (fs.existsSync(KEY_FILE)) {
    ENC_KEY = Buffer.from(fs.readFileSync(KEY_FILE, 'utf8').trim(), 'hex');
  } else {
    ENC_KEY = crypto.randomBytes(32);
    fs.writeFileSync(KEY_FILE, ENC_KEY.toString('hex'), { mode: 0o600 });
    console.log('[SECURITY] Chave de criptografia gerada e salva em', KEY_FILE);
  }
}
initEncryptionKey();

const ENC_PREFIX = 'enc1:';

function encryptField(plaintext) {
  if (!plaintext || typeof plaintext !== 'string') return plaintext;
  if (plaintext.startsWith(ENC_PREFIX)) return plaintext; // já criptografado
  try {
    const iv      = crypto.randomBytes(12);  // 96-bit IV para GCM
    const cipher  = crypto.createCipheriv('aes-256-gcm', ENC_KEY, iv);
    const enc     = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
    const authTag = cipher.getAuthTag();
    return ENC_PREFIX + iv.toString('hex') + ':' + authTag.toString('hex') + ':' + enc.toString('hex');
  } catch { return plaintext; }
}

function decryptField(value) {
  if (!value || typeof value !== 'string') return value;
  if (!value.startsWith(ENC_PREFIX)) return value; // plain text legado
  try {
    const parts   = value.slice(ENC_PREFIX.length).split(':');
    if (parts.length !== 3) return value;
    const iv      = Buffer.from(parts[0], 'hex');
    const authTag = Buffer.from(parts[1], 'hex');
    const enc     = Buffer.from(parts[2], 'hex');
    const decipher = crypto.createDecipheriv('aes-256-gcm', ENC_KEY, iv);
    decipher.setAuthTag(authTag);
    return decipher.update(enc) + decipher.final('utf8');
  } catch { return null; } // corruptos/inválidos retornam null
}

// Campos sensíveis que devem ser criptografados
const SENSITIVE_FIELDS = ['personalAccessToken', 'serviceRoleKey', 'anonKey'];

function encryptProject(p) {
  const out = { ...p };
  for (const f of SENSITIVE_FIELDS) if (out[f]) out[f] = encryptField(out[f]);
  return out;
}

function decryptProject(p) {
  const out = { ...p };
  for (const f of SENSITIVE_FIELDS) if (out[f]) out[f] = decryptField(out[f]);
  return out;
}

// ─── Data Layer ─────────────────────────────────────────────────────────────
const DATA_DIR = path.join(__dirname, 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });

const PROJECTS_FILE = path.join(DATA_DIR, 'projects.json');
const LOGS_FILE     = path.join(DATA_DIR, 'logs.json');

function loadProjects() {
  if (!fs.existsSync(PROJECTS_FILE)) return [];
  try {
    const raw = JSON.parse(fs.readFileSync(PROJECTS_FILE, 'utf8'));
    return raw.map(decryptProject);
  } catch { return []; }
}
function saveProjects(projects) {
  const encrypted = projects.map(encryptProject);
  fs.writeFileSync(PROJECTS_FILE, JSON.stringify(encrypted, null, 2));
}

// Mutex para evitar condições de corrida (race conditions) ao ler/gravar projects.json
let projectsLock = Promise.resolve();

function acquireProjectsLock() {
  let release;
  const nextLock = new Promise(resolve => { release = resolve; });
  const currentLock = projectsLock;
  projectsLock = nextLock;
  return currentLock.then(() => release);
}

async function updateProjectData(id, updates) {
  const release = await acquireProjectsLock();
  try {
    const projects = loadProjects();
    const idx = projects.findIndex(p => p.id === id);
    if (idx !== -1) {
      projects[idx] = { ...projects[idx], ...updates };
      saveProjects(projects);
      return projects[idx];
    }
    return null;
  } finally {
    release();
  }
}

function loadLogs() {
  if (!fs.existsSync(LOGS_FILE)) return [];
  try { return JSON.parse(fs.readFileSync(LOGS_FILE, 'utf8')); } catch { return []; }
}
function saveLogs(l) { fs.writeFileSync(LOGS_FILE, JSON.stringify(l, null, 2)); }

function addLog(projectId, status, message, details = null) {
  const logs = loadLogs();
  const entry = { id: `${Date.now()}-${Math.random().toString(36).slice(2,7)}`, projectId, status, message, details, timestamp: new Date().toISOString() };
  logs.unshift(entry);
  if (logs.length > 1000) logs.splice(1000);
  saveLogs(logs);
  return entry;
}

// ─── Helpers ─────────────────────────────────────────────────────────────────
function decodeJWT(token) {
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const payload = Buffer.from(parts[1], 'base64url').toString('utf8');
    return JSON.parse(payload);
  } catch { return null; }
}

function extractProjectRef(url) {
  try {
    const m = url.match(/https?:\/\/([a-z0-9]+)\.supabase\.co/);
    return m ? m[1] : null;
  } catch { return null; }
}

function buildSetupSQL(projectName) {
  return `-- ─────────────────────────────────────────────────────────────────────
-- Setup Anti-Pausa para: ${projectName}
-- Execute este script no SQL Editor do seu projeto Supabase
-- Acesse: https://supabase.com/dashboard/project/_/sql
-- ─────────────────────────────────────────────────────────────────────

CREATE TABLE IF NOT EXISTS _revisoes (
  id        BIGSERIAL     PRIMARY KEY,
  pinged_at TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
  source    TEXT          NOT NULL DEFAULT 'anti-pausa-supabase'
);

-- Ativar RLS
ALTER TABLE _revisoes ENABLE ROW LEVEL SECURITY;

-- Permitir leitura pública (para testar conexão)
DO $$ 
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = '_revisoes' AND policyname = 'allow_anon_select') THEN
    CREATE POLICY "allow_anon_select" ON _revisoes FOR SELECT TO anon USING (true);
  END IF;
END $$;

-- Permitir inserção pública (para os pings automáticos e testes de conexão)
DO $$ 
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = '_revisoes' AND policyname = 'allow_anon_insert') THEN
    CREATE POLICY "allow_anon_insert" ON _revisoes FOR INSERT TO anon WITH CHECK (true);
  END IF;
END $$;

-- Habilitar a extensão pg_cron
CREATE EXTENSION IF NOT EXISTS pg_cron;

-- Remover job antigo se já existir (evita duplicação)
DO $$ 
BEGIN
  IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
    IF EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'anti-pausa-keep-alive') THEN
      PERFORM cron.unschedule('anti-pausa-keep-alive');
    END IF;
  END IF;
END $$;

-- Agendar um novo job para rodar a cada 3 dias e manter o banco ativo
-- O job insere um registro e limpa logs antigos com mais de 30 dias
SELECT cron.schedule(
  'anti-pausa-keep-alive',
  '0 0 */3 * *',
  $$
    INSERT INTO _revisoes (source) VALUES ('pg_cron-keep-alive');
    DELETE FROM _revisoes WHERE pinged_at < NOW() - INTERVAL '30 days';
  $$
);`;
}

// ─── Core Logic ──────────────────────────────────────────────────────────────
// Erros do PostgREST que indicam que a tabela não existe no schema cache
function isTableNotFoundError(status, body) {
  const msg  = (body?.message || body?.error || '').toLowerCase();
  const hint = (body?.hint   || '').toLowerCase();
  const code  = body?.code || '';
  return (
    status === 404 ||
    code === 'PGRST116' ||                           // PostgREST: relation not found
    code === 'PGRST200' ||                           // PostgREST: schema cache miss
    msg.includes('does not exist') ||
    msg.includes('schema cache') ||                  // ← o erro que apareceu
    msg.includes('could not find the table') ||
    hint.includes('reload schema')
  );
}

async function testConnection(project) {
  const { url, anonKey, serviceRoleKey } = project;
  const key = serviceRoleKey || anonKey;

  try {
    const res = await fetch(`${url}/rest/v1/_revisoes?limit=1`, {
      headers: { 'apikey': key, 'Authorization': `Bearer ${key}` },
      signal: AbortSignal.timeout(10000)
    });

    if (res.ok) return { connected: true, tableExists: true, status: 'active' };

    const body = await res.json().catch(() => ({}));
    const msg  = (body?.message || body?.error || '').toLowerCase();

    // Tabela não encontrada (inclui schema cache miss)
    if (isTableNotFoundError(res.status, body)) {
      return { connected: true, tableExists: false, status: 'setup_required' };
    }

    // Projeto pausado
    if (res.status === 503 || msg.includes('paused') || msg.includes('inactive')) {
      return { connected: false, tableExists: false, status: 'paused', error: 'Projeto pausado pelo Supabase' };
    }

    return { connected: false, tableExists: false, status: 'error', error: `HTTP ${res.status}: ${body?.message || ''}` };

  } catch (err) {
    const msg = err.message || 'Timeout ou sem resposta';
    const isPaused = msg.includes('ECONNREFUSED') || msg.includes('ETIMEDOUT');
    return { connected: false, tableExists: false, status: isPaused ? 'paused' : 'error', error: msg };
  }
}

async function pingProject(project) {
  const { id, url, anonKey, serviceRoleKey, name } = project;
  const key = serviceRoleKey || anonKey;

  try {
    const res = await fetch(`${url}/rest/v1/_revisoes`, {
      method: 'POST',
      headers: {
        'apikey': key,
        'Authorization': `Bearer ${key}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=minimal'
      },
      body: JSON.stringify({ source: 'anti-pausa-supabase' }),
      signal: AbortSignal.timeout(15000)
    });

    if (res.ok || res.status === 201) {
      await updateProjectData(id, {
        lastPing: new Date().toISOString(),
        pingCount: (project.pingCount || 0) + 1,
        status: 'active',
        lastError: null
      });
      addLog(id, 'success', `Ping OK • ${name}`);
      return { success: true };
    }

    const body = await res.json().catch(() => ({}));
    const errMsg = body?.message || `HTTP ${res.status}`;

    // Schema cache miss → tabela existe mas cache ainda não atualizou
    let newStatus;
    if (isTableNotFoundError(res.status, body)) {
      newStatus = 'setup_required';
    } else if (res.status === 503) {
      newStatus = 'paused';
    } else {
      newStatus = 'error';
    }

    await updateProjectData(id, {
      lastError: errMsg,
      status: newStatus
    });
    addLog(id, 'error', `Ping falhou • ${name}: ${errMsg}`, { status: res.status });
    return { success: false, error: errMsg, status: newStatus };

  } catch (err) {
    await updateProjectData(id, {
      lastError: err.message,
      status: 'error'
    });
    addLog(id, 'error', `Ping falhou • ${name}: ${err.message}`);
    return { success: false, error: err.message };
  }
}

async function createTableWithPAT(project) {
  const ref = project.projectRef || extractProjectRef(project.url);
  const pat = project.personalAccessToken;
  if (!ref || !pat) return { success: false, error: 'PAT ou ref não encontrados' };

  const sql = `
    CREATE TABLE IF NOT EXISTS _revisoes (
      id BIGSERIAL PRIMARY KEY,
      pinged_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
      source TEXT NOT NULL DEFAULT 'anti-pausa-supabase'
    );
    ALTER TABLE _revisoes ENABLE ROW LEVEL SECURITY;
    DO $$ BEGIN
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = '_revisoes' AND policyname = 'allow_anon_insert') THEN
        EXECUTE 'CREATE POLICY allow_anon_insert ON _revisoes FOR INSERT TO anon WITH CHECK (true)';
      END IF;
      IF NOT EXISTS (SELECT 1 FROM pg_policies WHERE tablename = '_revisoes' AND policyname = 'allow_anon_select') THEN
        EXECUTE 'CREATE POLICY allow_anon_select ON _revisoes FOR SELECT TO anon USING (true)';
      END IF;
    END $$;

    -- Habilitar a extensão pg_cron
    CREATE EXTENSION IF NOT EXISTS pg_cron;

    -- Remover job antigo se já existir (evita duplicação)
    DO $$ 
    BEGIN
      IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_cron') THEN
        IF EXISTS (SELECT 1 FROM cron.job WHERE jobname = 'anti-pausa-keep-alive') THEN
          PERFORM cron.unschedule('anti-pausa-keep-alive');
        END IF;
      END IF;
    END $$;

    -- Agendar um novo job para rodar a cada 3 dias e manter o banco ativo
    SELECT cron.schedule(
      'anti-pausa-keep-alive',
      '0 0 */3 * *',
      $$
        INSERT INTO _revisoes (source) VALUES ('pg_cron-keep-alive');
        DELETE FROM _revisoes WHERE pinged_at < NOW() - INTERVAL '30 days';
      $$
    );

    -- Força o PostgREST a recarregar o cache de schema imediatamente
    NOTIFY pgrst, 'reload schema';
  `;

  try {
    const res = await fetch(`https://api.supabase.com/v1/projects/${ref}/database/query`, {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${pat}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ query: sql }),
      signal: AbortSignal.timeout(20000)
    });

    if (res.ok) {
      // Aguarda 4 segundos para o PostgREST processar o NOTIFY e atualizar o cache
      await new Promise(resolve => setTimeout(resolve, 4000));
      return { success: true };
    }

    const body = await res.json().catch(() => ({}));
    return { success: false, error: body?.message || `HTTP ${res.status}` };
  } catch (err) {
    return { success: false, error: err.message };
  }
}


// \u2500\u2500\u2500 Auth Middleware \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
const DASHBOARD_PASSWORD = process.env.DASHBOARD_PASSWORD || 'pJLFZIvBVvKvw2';
// Tokens: Map<token, expiresAt>
const validTokens = new Map();

// Rate limiting em mem\u00f3ria: Map<ip, {count, resetAt}>
const loginAttempts = new Map();
const MAX_ATTEMPTS  = 2;
const WINDOW_MS     = 15 * 60 * 1000; // 15 minutos

function checkRateLimit(ip) {
  const now   = Date.now();
  const entry = loginAttempts.get(ip) || { count: 0, resetAt: now + WINDOW_MS };
  if (now > entry.resetAt) { entry.count = 0; entry.resetAt = now + WINDOW_MS; }
  entry.count++;
  loginAttempts.set(ip, entry);
  return entry.count > MAX_ATTEMPTS;
}

function generateToken() {
  return crypto.randomBytes(32).toString('hex');
}

function timingSafePasswordCheck(input, expected) {
  // Compara\u00e7\u00e3o em tempo constante para prevenir timing attacks
  const a = Buffer.alloc(64, 0); const b = Buffer.alloc(64, 0);
  Buffer.from(input.slice(0, 64)).copy(a);
  Buffer.from(expected.slice(0, 64)).copy(b);
  return crypto.timingSafeEqual(a, b) && input === expected;
}

function isAuthenticated(req) {
  if (!DASHBOARD_PASSWORD) return true;
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '').trim()
             || req.headers['x-auth-token']
             || '';
  const expiresAt = validTokens.get(token);
  if (!expiresAt || Date.now() > expiresAt) {
    if (expiresAt) validTokens.delete(token); // limpa expirado
    return false;
  }
  return true;
}

function requireAuth(req, res, next) {
  if (isAuthenticated(req)) return next();
  res.status(401).json({ error: 'N\u00e3o autenticado', requireAuth: true });
}

// Login com rate limiting e timing-safe
app.post('/api/auth/login', (req, res) => {
  const ip = req.ip || req.socket.remoteAddress || 'unknown';
  if (checkRateLimit(ip)) {
    return res.status(429).json({ error: 'Muitas tentativas. Tente em 15 minutos.' });
  }

  const { password } = req.body || {};
  if (!DASHBOARD_PASSWORD) return res.json({ success: true, token: null, noAuth: true });
  if (!password || !timingSafePasswordCheck(String(password), DASHBOARD_PASSWORD)) {
    // Delay artificial para dificultar enumera\u00e7\u00e3o
    return setTimeout(() => res.status(401).json({ error: 'Senha incorreta' }), 400);
  }

  const token     = generateToken();
  const expiresAt = Date.now() + 30 * 24 * 3600 * 1000; // 30 dias
  validTokens.set(token, expiresAt);
  res.json({ success: true, token });
});


// Check auth status
app.get('/api/auth/check', (req, res) => {
  res.json({
    authenticated: isAuthenticated(req),
    passwordRequired: !!DASHBOARD_PASSWORD
  });
});

// Logout
app.post('/api/auth/logout', (req, res) => {
  const authHeader = req.headers['authorization'] || '';
  const token = authHeader.replace('Bearer ', '').trim();
  validTokens.delete(token);
  res.json({ success: true });
});

// ─── API Routes ──────────────────────────────────────────────────────────────
// Todas as rotas /api/* (exceto auth) requerem autenticação
app.use('/api', (req, res, next) => {
  if (req.path.startsWith('/auth/')) return next(); // rotas de auth são livres
  requireAuth(req, res, next);
});

// Test connection before adding
app.post('/api/projects/test', async (req, res) => {
  const { url, anonKey, serviceRoleKey } = req.body;
  if (!url || !anonKey) return res.status(400).json({ error: 'URL e Anon Key são obrigatórios' });

  const jwt = decodeJWT(anonKey);
  const ref = jwt?.ref || extractProjectRef(url);
  const result = await testConnection({ url, anonKey, serviceRoleKey });

  res.json({ ...result, projectRef: ref, keyInfo: jwt ? { role: jwt.role, ref: jwt.ref, exp: jwt.exp } : null });
});

// List all projects (keys masked)
app.get('/api/projects', (req, res) => {
  const projects = loadProjects().map(p => ({
    ...p,
    anonKey: p.anonKey ? `${p.anonKey.substring(0, 12)}...` : null,
    serviceRoleKey: p.serviceRoleKey ? '[SET]' : null,
    personalAccessToken: p.personalAccessToken ? '[SET]' : null
  }));
  res.json(projects);
});

// Add project
app.post('/api/projects', async (req, res) => {
  const { name, url, anonKey, serviceRoleKey, personalAccessToken } = req.body;
  if (!name || !url || !anonKey) return res.status(400).json({ error: 'Nome, URL e Anon Key são obrigatórios' });

  const release = await acquireProjectsLock();
  let project;
  try {
    const projects = loadProjects();
    if (projects.find(p => p.url.trim() === url.trim())) {
      release();
      return res.status(400).json({ error: 'Já existe um projeto com esta URL' });
    }

    const jwt = decodeJWT(anonKey);
    project = {
      id: `proj_${Date.now()}`,
      name,
      url: url.replace(/\/$/, ''),
      anonKey,
      serviceRoleKey: serviceRoleKey || null,
      personalAccessToken: personalAccessToken || null,
      projectRef: jwt?.ref || extractProjectRef(url),
      status: 'checking',
      tableExists: false,
      connected: false,
      lastPing: null,
      pingCount: 0,
      lastError: null,
      enabled: true,
      createdAt: new Date().toISOString()
    };

    projects.push(project);
    saveProjects(projects);
  } finally {
    release();
  }

  addLog(project.id, 'info', `Projeto "${name}" adicionado`);

  // Test + auto-setup async
  (async () => {
    try {
      const result = await testConnection(project);
      let updatedProj = await updateProjectData(project.id, result);
      if (!updatedProj) return;

      if (!result.tableExists && personalAccessToken) {
        const setup = await createTableWithPAT(updatedProj);
        if (setup.success) {
          updatedProj = await updateProjectData(project.id, { status: 'active', tableExists: true });
          addLog(project.id, 'success', `Tabela _revisoes criada automaticamente`);
          if (updatedProj) await pingProject(updatedProj);
          return;
        } else {
          addLog(project.id, 'warning', `Auto-setup falhou: ${setup.error}. Execute o SQL manualmente.`);
          await updateProjectData(project.id, { status: 'setup_required', lastError: setup.error });
        }
      }

      addLog(project.id, result.connected ? 'success' : 'error',
        result.connected ? `Conectado! Status: ${result.status}` : `Falha de conexão: ${result.error}`);
    } catch (err) {
      console.error(`[ADD-ASYNC] Erro ao processar projeto ${project.name}:`, err);
      await updateProjectData(project.id, { status: 'error', lastError: err.message });
      addLog(project.id, 'error', `Erro ao inicializar projeto "${name}": ${err.message}`);
    }
  })();

  res.json({
    ...project,
    anonKey: `${anonKey.substring(0, 12)}...`,
    serviceRoleKey: serviceRoleKey ? '[SET]' : null,
    personalAccessToken: personalAccessToken ? '[SET]' : null
  });
});

// Delete project
app.delete('/api/projects/:id', async (req, res) => {
  const release = await acquireProjectsLock();
  try {
    const projects = loadProjects();
    const proj = projects.find(p => p.id === req.params.id);
    saveProjects(projects.filter(p => p.id !== req.params.id));
    if (proj) addLog(proj.id, 'info', `Projeto "${proj.name}" removido`);
    res.json({ success: true });
  } finally {
    release();
  }
});

// Update (enable/disable/rename)
app.patch('/api/projects/:id', async (req, res) => {
  const release = await acquireProjectsLock();
  try {
    const projects = loadProjects();
    const idx = projects.findIndex(p => p.id === req.params.id);
    if (idx === -1) return res.status(404).json({ error: 'Projeto não encontrado' });
    const { enabled, name } = req.body;
    if (typeof enabled !== 'undefined') projects[idx].enabled = enabled;
    if (name) projects[idx].name = name;
    saveProjects(projects);
    res.json({ success: true });
  } finally {
    release();
  }
});

// Manual ping
app.post('/api/projects/:id/ping', async (req, res) => {
  const project = loadProjects().find(p => p.id === req.params.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado' });
  const result = await pingProject(project);
  res.json(result);
});

// Get setup SQL or auto-create
app.post('/api/projects/:id/setup', async (req, res) => {
  const project = loadProjects().find(p => p.id === req.params.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado' });

  if (project.personalAccessToken) {
    const result = await createTableWithPAT(project);
    if (result.success) {
      const updatedProj = await updateProjectData(project.id, { status: 'active', tableExists: true });
      addLog(project.id, 'success', `Tabela _revisoes criada com PAT`);
      if (updatedProj) await pingProject(updatedProj);
      return res.json({ success: true, autoCreated: true });
    }
    return res.json({ success: false, autoCreated: false, error: result.error, sql: buildSetupSQL(project.name) });
  }

  res.json({ success: false, requiresManualSetup: true, sql: buildSetupSQL(project.name) });
});

// Confirm manual SQL was executed
app.post('/api/projects/:id/confirm-setup', async (req, res) => {
  const projectsBefore = loadProjects();
  const projBefore = projectsBefore.find(p => p.id === req.params.id);
  if (!projBefore) return res.status(404).json({ error: 'Projeto não encontrado' });

  // Se tem PAT, envia NOTIFY para recarregar o schema cache antes de testar
  if (projBefore.personalAccessToken) {
    const ref = projBefore.projectRef || extractProjectRef(projBefore.url);
    if (ref) {
      await fetch(`https://api.supabase.com/v1/projects/${ref}/database/query`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${projBefore.personalAccessToken}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({ query: `NOTIFY pgrst, 'reload schema';` }),
        signal: AbortSignal.timeout(10000)
      }).catch(() => {});
      // Aguarda o PostgREST processar
      await new Promise(resolve => setTimeout(resolve, 3000));
    }
  }

  const result = await testConnection(projBefore);
  if (result.tableExists) {
    const updatedProj = await updateProjectData(req.params.id, {
      status: 'active',
      tableExists: true,
      connected: true
    });
    addLog(req.params.id, 'success', `Setup confirmado para "${projBefore.name}"`);
    if (updatedProj) await pingProject(updatedProj);
    return res.json({ success: true });
  }
  res.json({ success: false, error: 'Tabela ainda não encontrada. Verifique se o SQL foi executado.' });
});

// Refresh project status
app.post('/api/projects/:id/refresh', async (req, res) => {
  const projects = loadProjects();
  const project = projects.find(p => p.id === req.params.id);
  if (!project) return res.status(404).json({ error: 'Projeto não encontrado' });

  const result = await testConnection(project);
  await updateProjectData(req.params.id, result);
  res.json({ success: true, ...result });
});

// Pinga TODOS os projetos agora (ignora status, só respeita enabled)
app.post('/api/ping-all', async (req, res) => {
  const projects = loadProjects().filter(p => p.enabled !== false);
  if (!projects.length) return res.json({ results: [], pinged: 0 });

  res.json({ started: true, count: projects.length });

  // Executa em background
  (async () => {
    for (const project of projects) {
      // Se tem PAT e o status é setup_required ou checking, tenta criar/reativar tabela
      if (project.personalAccessToken && (project.status === 'setup_required' || project.status === 'checking' || project.status === 'error')) {
        const ref = project.projectRef || extractProjectRef(project.url);
        if (ref) {
          console.log(`[PING-ALL] Recarregando schema cache de ${project.name}...`);
          await fetch(`https://api.supabase.com/v1/projects/${ref}/database/query`, {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${project.personalAccessToken}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({ query: `NOTIFY pgrst, 'reload schema';` }),
            signal: AbortSignal.timeout(10000)
          }).catch(() => {});
          await new Promise(resolve => setTimeout(resolve, 3000));

          // Testa se a tabela agora existe
          const connResult = await testConnection(project);
          if (!connResult.tableExists) {
            // Não existe de fato — cria
            const setup = await createTableWithPAT({ ...project });
            if (setup.success) {
              const ps = loadProjects();
              const idx = ps.findIndex(p => p.id === project.id);
              if (idx !== -1) { ps[idx].status = 'active'; ps[idx].tableExists = true; saveProjects(ps); }
              addLog(project.id, 'success', `Tabela criada e pronta • ${project.name}`);
              // Usa a versão atualizada do project
              await pingProject(loadProjects().find(p => p.id === project.id) || project);
              continue;
            }
          }
        }
      }

      console.log(`[PING-ALL] Pingando ${project.name}...`);
      await pingProject(project);
    }
  })();
});

// Logs
app.get('/api/logs', (req, res) => {
  const { projectId, limit = 100 } = req.query;
  let logs = loadLogs();
  if (projectId) logs = logs.filter(l => l.projectId === projectId);
  res.json(logs.slice(0, parseInt(limit)));
});

// Overall status
app.get('/api/status', (req, res) => {
  const projects = loadProjects();
  const active      = projects.filter(p => p.status === 'active' && p.enabled).length;
  const setupReq    = projects.filter(p => p.status === 'setup_required').length;
  const paused      = projects.filter(p => p.status === 'paused').length;
  const total       = projects.length;

  const nextPingProject = projects
    .filter(p => p.status === 'active' && p.enabled && p.lastPing)
    .sort((a, b) => new Date(a.lastPing) - new Date(b.lastPing))[0];

  let nextPingMs = null;
  if (nextPingProject) {
    const next = new Date(nextPingProject.lastPing).getTime() + 47 * 3600 * 1000;
    nextPingMs = Math.max(0, next - Date.now());
  }

  res.json({ active, total, setupReq, paused, nextPingMs, uptime: process.uptime() });
});

// ─── PAT Discovery (lista projetos via Management API) ───────────────────────
async function fetchAllProjectsFromPAT(pat) {
  // 1. Lista todos os projetos da conta
  const projRes = await fetch('https://api.supabase.com/v1/projects', {
    headers: { 'Authorization': `Bearer ${pat}` },
    signal: AbortSignal.timeout(15000)
  });

  if (!projRes.ok) {
    const body = await projRes.json().catch(() => ({}));
    throw new Error(body?.message || `Erro ${projRes.status} ao listar projetos`);
  }

  const allProjects = await projRes.json();  // array de projetos

  // 2. Para cada projeto, busca as API keys
  const enriched = await Promise.all(allProjects.map(async (proj) => {
    try {
      const keyRes = await fetch(`https://api.supabase.com/v1/projects/${proj.ref}/api-keys`, {
        headers: { 'Authorization': `Bearer ${pat}` },
        signal: AbortSignal.timeout(10000)
      });

      let anonKey = null;
      let serviceRoleKey = null;

      if (keyRes.ok) {
        const keys = await keyRes.json();
        // Prefere publishable, depois anon (legacy)
        const anonEntry = keys.find(k => k.name === 'default' && k.type === 'publishable')
                       || keys.find(k => k.name === 'anon');
        const svcEntry  = keys.find(k => k.name === 'service_role');
        anonKey        = anonEntry?.api_key || null;
        serviceRoleKey = svcEntry?.api_key  || null;
      }

      return {
        ref:           proj.ref,
        name:          proj.name,
        status:        proj.status,         // ACTIVE_HEALTHY | INACTIVE | PAUSED_ACTIVE
        region:        proj.region,
        orgId:         proj.organization_id,
        url:           `https://${proj.ref}.supabase.co`,
        anonKey,
        serviceRoleKey,
        createdAt:     proj.created_at
      };
    } catch (err) {
      return {
        ref:    proj.ref,
        name:   proj.name,
        status: proj.status,
        url:    `https://${proj.ref}.supabase.co`,
        anonKey: null,
        serviceRoleKey: null,
        error:  err.message
      };
    }
  }));

  return enriched;
}

// Descobre projetos via PAT (sem adicionar ainda)
app.post('/api/discover', async (req, res) => {
  const { pat } = req.body;
  if (!pat) return res.status(400).json({ error: 'Personal Access Token é obrigatório' });

  try {
    const discovered = await fetchAllProjectsFromPAT(pat);
    const existing   = loadProjects().map(p => p.projectRef || extractProjectRef(p.url));

    const result = discovered.map(d => ({
      ref:                  d.ref,
      name:                 d.name,
      status:               d.status,
      region:               d.region,
      orgId:                d.orgId,
      url:                  d.url,
      createdAt:            d.createdAt,
      alreadyAdded:         existing.includes(d.ref),
      anonKeyPreview:       d.anonKey        ? `${d.anonKey.substring(0,12)}...`        : null,
      serviceRoleKeyPreview:d.serviceRoleKey ? `${d.serviceRoleKey.substring(0,12)}...` : null,
      hasAnonKey:           !!d.anonKey,
      hasServiceRoleKey:    !!d.serviceRoleKey
    }));

    res.json({ projects: result, count: result.length });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// Importa projetos selecionados via PAT (cria tabela automaticamente)
app.post('/api/import', async (req, res) => {
  const { pat, refs } = req.body;   // refs = array de project refs para importar
  if (!pat || !refs?.length) return res.status(400).json({ error: 'PAT e refs são obrigatórios' });

  try {
    const discovered = await fetchAllProjectsFromPAT(pat);
    const toImport   = discovered.filter(d => refs.includes(d.ref));
    const existing   = loadProjects();
    const results    = [];

    for (const d of toImport) {
      // Pula se já existe
      if (existing.find(p => (p.projectRef || extractProjectRef(p.url)) === d.ref)) {
        results.push({ ref: d.ref, name: d.name, status: 'skipped', reason: 'Já adicionado' });
        continue;
      }

      if (!d.anonKey) {
        results.push({ ref: d.ref, name: d.name, status: 'error', reason: 'Anon Key não encontrada' });
        continue;
      }

      const project = {
        id:                   `proj_${Date.now()}_${d.ref}`,
        name:                 d.name,
        url:                  d.url,
        anonKey:              d.anonKey,
        serviceRoleKey:       d.serviceRoleKey || null,
        personalAccessToken:  pat,
        projectRef:           d.ref,
        organization:         d.orgId,
        region:               d.region,
        status:               'checking',
        tableExists:          false,
        connected:            false,
        lastPing:             null,
        pingCount:            0,
        lastError:            null,
        enabled:              true,
        importedViaPAT:       true,
        createdAt:            new Date().toISOString()
      };

      const release = await acquireProjectsLock();
      try {
        const projs = loadProjects();
        projs.push(project);
        saveProjects(projs);
      } finally {
        release();
      }
      addLog(project.id, 'info', `Projeto "${d.name}" importado via PAT`);

      // Cria tabela + pinga (async)
      (async () => {
        try {
          const connResult = await testConnection(project);
          let updatedProj = await updateProjectData(project.id, connResult);
          if (!updatedProj) return;

          if (!connResult.tableExists) {
            const setup = await createTableWithPAT(updatedProj);
            if (setup.success) {
              updatedProj = await updateProjectData(project.id, { status: 'active', tableExists: true });
              addLog(project.id, 'success', `Tabela _revisoes criada para "${d.name}"`);
              if (updatedProj) await pingProject(updatedProj);
              return;
            } else {
              addLog(project.id, 'warning', `Não foi possível criar tabela para "${d.name}": ${setup.error}`);
              await updateProjectData(project.id, { status: 'setup_required', lastError: setup.error });
            }
          } else {
            await pingProject(updatedProj);
          }
        } catch (err) {
          console.error(`[IMPORT-ASYNC] Erro ao processar projeto ${project.name}:`, err);
          await updateProjectData(project.id, { status: 'error', lastError: err.message });
          addLog(project.id, 'error', `Erro ao inicializar projeto "${d.name}": ${err.message}`);
        }
      })();

      results.push({ ref: d.ref, name: d.name, status: 'imported' });
    }

    res.json({ results, imported: results.filter(r => r.status === 'imported').length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ─── Scheduler ──────────────────────────────────────────────────────────────
async function runScheduledPings() {
  const projects = loadProjects();
  const now = Date.now();

  for (const project of projects) {
    if (!project.enabled) continue;

    // Projetos travados em 'checking' ou 'error' há mais de 5 minutos: tenta recuperar
    if (project.status === 'checking' || project.status === 'error') {
      const age = (now - new Date(project.createdAt || 0).getTime()) / 60000;
      if (age > 5) {
        console.log(`[SCHED] Recuperando projeto travado: ${project.name} (status: ${project.status})`);
        const connResult = await testConnection(project);
        await updateProjectData(project.id, connResult);
        continue;
      }
    }

    // Projetos ativos: pinga se passou 47h
    if (project.status !== 'setup_required' && project.status !== 'paused') {
      const lastPing = project.lastPing ? new Date(project.lastPing).getTime() : 0;
      const hoursAgo = (now - lastPing) / 3600000;
      if (hoursAgo >= 47) {
        console.log(`[SCHED] Pingando ${project.name}...`);
        await pingProject(project);
      }
    }
  }
}

// Roda a cada hora
cron.schedule('0 * * * *', () => {
  console.log(`[CRON] ${new Date().toISOString()} Rodando checks agendados...`);
  runScheduledPings();
});

// ─── Start ────────────────────────────────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`\n🟢 Anti-Pausa Supabase rodando em http://localhost:${PORT}`);
  console.log(`📊 Abrindo dashboard...\n`);

  // Initial check on startup
  setTimeout(async () => {
    const projects = loadProjects();
    for (const project of projects) {
      if (!project.enabled || project.status === 'setup_required') continue;
      const lastPing = project.lastPing ? new Date(project.lastPing).getTime() : 0;
      if ((Date.now() - lastPing) / 3600000 >= 47) {
        console.log(`[STARTUP] Pingando ${project.name}...`);
        await pingProject(project);
      }
    }
  }, 3000);
});
