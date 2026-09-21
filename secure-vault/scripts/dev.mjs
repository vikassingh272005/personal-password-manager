#!/usr/bin/env node
/**
 * One-command dev launcher: Postgres (Docker) → API (cargo) → web (Next.js)
 * → demo seed → health checks.
 *
 *   npm run dev            # from the repo root or secure-vault/
 *   node scripts/dev.mjs   # equivalent
 *
 * Flags:
 *   --no-seed      skip the demo seed
 *   --rebuild-web  force a fresh Next.js production build
 *   --no-web       start only Postgres + API
 *
 * Idempotent: safe to run repeatedly. Skips what is already up to date and
 * reports where the stack lives when everything is running.
 */

import { spawn, execSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import net from 'node:net';
import { fileURLToPath } from 'node:url';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const WEB_DIR = path.join(ROOT, 'apps', 'web');
const API_DIR = ROOT;
const RUN_DIR = path.join(ROOT, '.dev-run');
const API = 'http://localhost:3001';
const WEB = 'http://localhost:3000';
const DB_URL = 'postgres://postgres:postgres@localhost:5433/secure_vault';

const SEED = !process.argv.includes('--no-seed');
const NO_WEB = process.argv.includes('--no-web');
const REBUILD_WEB = process.argv.includes('--rebuild-web');

const log = (msg) => console.log(`[dev] ${msg}`);
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function portOpen(port, host = '127.0.0.1') {
  return new Promise((resolve) => {
    const socket = net.connect({ port, host, timeout: 800 });
    socket.once('connect', () => { socket.destroy(); resolve(true); });
    socket.once('timeout', () => { socket.destroy(); resolve(false); });
    socket.once('error', () => resolve(false));
  });
}

function sh(cmd, opts = {}) {
  return execSync(cmd, { stdio: 'pipe', encoding: 'utf8', ...opts });
}

function spawnDetached(name, cmd, args, cwd, logFile) {
  fs.mkdirSync(RUN_DIR, { recursive: true });
  const out = fs.openSync(logFile, 'a');
  const child = spawn(cmd, args, {
    cwd,
    stdio: ['ignore', out, out],
    detached: true,
    shell: process.platform === 'win32',
    env: { ...process.env, DATABASE_URL: DB_URL, PORT: '3001', RUST_LOG: 'info' },
  });
  child.unref();
  console.log(`       logs: ${logFile}`);
  return child;
}

async function waitFor(desc, url, timeoutS = 60) {
  const deadline = Date.now() + timeoutS * 1000;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(url, { signal: AbortSignal.timeout(1500) });
      if (res.ok || res.status === 404 || res.status === 401) return true;
    } catch { /* not up yet */ }
    await sleep(1000);
  }
  throw new Error(`${desc} did not become healthy within ${timeoutS}s`);
}

// ---- 1. Postgres ------------------------------------------------------------

async function ensurePostgres() {
  log('checking Postgres (docker, port 5433)…');
  let dockerOk = false;
  try { sh('docker info', { timeout: 8000 }); dockerOk = true; } catch { /* below */ }

  if (!dockerOk) {
    log('Docker daemon is down — starting Docker Desktop…');
    try {
      if (process.platform === 'win32') {
        spawnDetached('docker-desktop', 'powershell', [
          '-NoProfile', '-Command',
          'Start-Process -FilePath \'C:\\Program Files\\Docker\\Docker\\Docker Desktop.exe\'',
        ], ROOT, path.join(RUN_DIR, 'docker-desktop.log'));
      } else if (process.platform === 'darwin') {
        spawnDetached('docker-desktop', 'open', ['-a', 'Docker'], ROOT, path.join(RUN_DIR, 'docker-desktop.log'));
      }
      for (let i = 0; i < 45; i++) {
        try { sh('docker info', { timeout: 4000 }); dockerOk = true; break; } catch { await sleep(2000); }
      }
    } catch { /* fallthrough */ }
    if (!dockerOk) throw new Error('Could not start Docker. Start it manually and re-run.');
  }

  const running = (() => {
    try { return sh('docker ps --format "{{.Names}}"', { timeout: 8000 }); } catch { return ''; }
  })().split('\n').map((s) => s.trim());

  if (!running.includes('secure-vault-postgres-5433')) {
    log('creating Postgres container on :5433…');
    sh(
      'docker run -d --name secure-vault-postgres-5433 -p 5433:5432 ' +
      '-e POSTGRES_PASSWORD=postgres -e POSTGRES_DB=secure_vault postgres:16-alpine',
      { timeout: 120000 }
    );
  } else {
    const status = sh('docker inspect -f "{{.State.Status}}" secure-vault-postgres-5433').trim();
    if (status !== 'running') {
      log('starting existing Postgres container…');
      sh('docker start secure-vault-postgres-5433', { timeout: 30000 });
    }
  }
  await waitFor('Postgres', API, 90).catch(() => {}); // warm-up grace
  // Health-check the database itself.
  const deadline = Date.now() + 60000;
  while (Date.now() < deadline) {
    try {
      sh('docker exec secure-vault-postgres-5433 pg_isready -U postgres -d secure_vault', { timeout: 5000 });
      log('Postgres is ready');
      return;
    } catch { await sleep(1500); }
  }
  throw new Error('Postgres never became ready');
}

// ---- 2. API -----------------------------------------------------------------

function exeName() {
  return process.platform === 'win32' ? 'secure-vault.exe' : 'secure-vault';
}

async function ensureApi() {
  if (await portOpen(3001)) {
    try {
      const res = await fetch(`${API}/health`, { signal: AbortSignal.timeout(1500) });
      if (res.ok) { log('API already running on :3001'); return; }
    } catch { /* stale listener — fall through and try to start anyway */ }
  }

  const exe = path.join(API_DIR, 'target', 'debug', exeName());
  const needsBuild = !fs.existsSync(exe);
  if (needsBuild) {
    log('building API (first run compiles ~2 min)…');
    sh('cargo build -p secure-vault-api', { cwd: API_DIR, timeout: 900000, stdio: 'inherit' });
  }
  log('starting API…');
  spawnDetached('api', exe, [], API_DIR, path.join(RUN_DIR, 'api.log'));
  await waitFor('API', `${API}/health`);
  log('API is healthy on :3001');
}

// ---- 3. Web -----------------------------------------------------------------

async function ensureWeb() {
  if (NO_WEB) return;
  if (await portOpen(3000)) {
    log('web already running on :3000');
    return;
  }

  const prodBuild = path.join(WEB_DIR, '.next', 'BUILD_ID');
  const hasBuild = fs.existsSync(prodBuild);
  if (!hasBuild || REBUILD_WEB) {
    log(hasBuild ? 'rebuilding web (--rebuild-web)…' : 'building web (next build)…');
    sh('npm run build', { cwd: WEB_DIR, timeout: 900000, stdio: 'inherit' });
  }
  log('starting web…');
  spawnDetached('web', 'npx', ['next', 'start', '-p', '3000'], WEB_DIR, path.join(RUN_DIR, 'web.log'));
  await waitFor('web', WEB);
  log('web is up on :3000');
}

// ---- 4. Seed ----------------------------------------------------------------

async function ensureSeed() {
  if (!SEED) return;
  try {
    const res = await fetch(`${API}/api/v1/auth/login`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'demo@securevault.local', password: 'demo-password-123' }),
      signal: AbortSignal.timeout(5000),
    });
    if (res.ok || res.status === 202) { log('demo account already seeded'); return; }
  } catch { /* fall through to seed */ }

  log('seeding demo account…');
  sh('node scripts/seed-demo.mjs', { cwd: ROOT, stdio: 'inherit', timeout: 120000 });
}

// ---- main -------------------------------------------------------------------

try {
  await ensurePostgres();
  await ensureApi();
  await ensureWeb();
  await ensureSeed();

  console.log('');
  console.log('  SecureVault is running:');
  console.log('    web:      http://localhost:3000');
  console.log('    api:      http://localhost:3001/health');
  console.log('    login:    demo@securevault.local / demo-password-123');
  console.log('    master:   demo-master-456');
  console.log('');
  console.log('  Stop: taskkill /IM secure-vault.exe /F  ·  docker stop secure-vault-postgres-5433');
} catch (err) {
  console.error(`[dev] ${err.message}`);
  process.exit(1);
}
