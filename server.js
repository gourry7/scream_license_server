// 간단한 TCP 라이센스 서버
// - 포트: 2000
// - 프로토콜: 클라이언트가 JSON 한 줄을 전송하면
//             (예: {"deviceId":"<hex>","company":"ACME"}\\n)
//             서버가 88바이트 라이센스 바이너리를 응답
//
// 라이센스 포맷 (바이너리, 총 88바이트, 만료 시간 없음)
// 0-3   : magic "SCRM"
// 4     : version (1)
// 5-7   : reserved (0)
// 8-23  : device_id (16 bytes)
// 24-87 : MAC(64 bytes) = SHAKE256(ENCRYPTION_KEY || device_id)[0..63]

const net = require('net');
const http = require('http');
const fs = require('fs');
const path = require('path');
const { shake256 } = require('js-sha3');

const TCP_PORT = 2000;
const TCP_HOST = '0.0.0.0'; // 실제 서비스 시 169.211.234.68 에서 바인딩

const HTTP_PORT = 3000;
const HTTP_HOST = '0.0.0.0';

// Render 무료 티어 등: 로컬 디스크는 재시작 시 유실됨
// → LICENSE_GITHUB_TOKEN 이면 기본으로 github.com/gourry7/scream_license_server 의 data/licenses.json 을 읽고 커밋
//   (LICENSE_GITHUB_REPO 로 덮어쓰기 가능). 또는 DATABASE_URL, LICENSE_DATA_DIR
/** 기본 GitHub 저장소 (LICENSE_GITHUB_TOKEN 만 넣을 때 사용). 환경변수 DEFAULT_LICENSE_GITHUB_REPO 로 변경 가능 */
const DEFAULT_LICENSE_GITHUB_REPO = (
  process.env.DEFAULT_LICENSE_GITHUB_REPO || 'gourry7/scream_license_server'
).trim();
const DATA_DIR = process.env.LICENSE_DATA_DIR
  ? path.resolve(process.env.LICENSE_DATA_DIR)
  : path.join(__dirname, 'data');
const LICENSE_DB_PATH = path.join(DATA_DIR, 'licenses.json');

/** @type {'file' | 'postgres' | 'github'} */
let storageMode = 'file';

/** @type {import('pg').Pool | null} */
let pgPool = null;
/** PostgreSQL 사용 시 메모리 캐시 */
let pgDbCache = null;

/** GitHub Contents API 사용 시 */
let githubDbCache = null;
/** @type {string | null} 현재 파일 SHA (업데이트 시 필요) */
let githubFileSha = null;
let githubSaveChain = Promise.resolve();
let githubOwner = '';
let githubRepo = '';
let githubPath = 'data/licenses.json';
let githubBranch = 'main';
let githubToken = '';

const GITHUB_API = 'https://api.github.com';

function githubContentsUrl() {
  const enc = githubPath.split('/').map(encodeURIComponent).join('/');
  return `${GITHUB_API}/repos/${githubOwner}/${githubRepo}/contents/${enc}`;
}

async function githubRequest(method, url, jsonBody) {
  const headers = {
    Accept: 'application/vnd.github+json',
    Authorization: `Bearer ${githubToken}`,
    'X-GitHub-Api-Version': '2022-11-28',
    'User-Agent': 'scream-license-server',
  };
  if (jsonBody !== undefined) {
    headers['Content-Type'] = 'application/json';
  }
  const res = await fetch(url, {
    method,
    headers,
    body: jsonBody !== undefined ? JSON.stringify(jsonBody) : undefined,
  });
  const text = await res.text();
  let parsed = null;
  try {
    parsed = text ? JSON.parse(text) : null;
  } catch {
    parsed = null;
  }
  if (!res.ok) {
    const msg = parsed && parsed.message ? parsed.message : text || res.statusText;
    const err = new Error(`GitHub ${res.status}: ${msg}`);
    err.status = res.status;
    throw err;
  }
  return parsed;
}

async function githubLoadInitial() {
  const getUrl = `${githubContentsUrl()}?ref=${encodeURIComponent(githubBranch)}`;
  try {
    const meta = await githubRequest('GET', getUrl);
    githubFileSha = meta.sha;
    const raw = Buffer.from(meta.content, 'base64').toString('utf8');
    const parsed = JSON.parse(raw);
    if (!parsed.devices) parsed.devices = {};
    if (!parsed.issues) parsed.issues = [];
    githubDbCache = parsed;
  } catch (e) {
    if (e.status === 404) {
      githubDbCache = { devices: {}, issues: [] };
      githubFileSha = null;
      await githubPersistNow();
    } else {
      throw e;
    }
  }
}

async function githubPersistNow() {
  const content = Buffer.from(JSON.stringify(githubDbCache, null, 2), 'utf8').toString('base64');
  const body = {
    message: `license: update ${new Date().toISOString()}`,
    content,
    branch: githubBranch,
  };
  if (githubFileSha) {
    body.sha = githubFileSha;
  }
  const res = await githubRequest('PUT', githubContentsUrl(), body);
  if (res && res.content && res.content.sha) {
    githubFileSha = res.content.sha;
  }
}

function githubQueuePersist() {
  githubSaveChain = githubSaveChain
    .then(() => githubPersistNow())
    .catch(async (e) => {
      console.error('GitHub persist failed:', e.message || e);
      if (e.status === 409) {
        try {
          const getUrl = `${githubContentsUrl()}?ref=${encodeURIComponent(githubBranch)}`;
          const meta = await githubRequest('GET', getUrl);
          githubFileSha = meta.sha;
          await githubPersistNow();
        } catch (e2) {
          console.error('GitHub retry after conflict failed:', e2.message || e2);
        }
      }
    });
}

// C 코드의 ENCRYPTION_KEY 와 동일한 비밀키 (MAC 용)
// 0x4B,0x59,0x42,0x45,0x52,0x5F,0x53,0x43,0x52,0x45,0x41,0x4D,0x5F,0x4D,0x4F,0x44,
// 0x45,0x4C,0x5F,0x32,0x30,0x32,0x35,0x5F,0x56,0x31,0x5F,0x53,0x45,0x43,0x52,0x45
const MAC_KEY = Buffer.from(
  '4b594245525f53435245414d5f4d4f44454c5f323032355f56315f5345435245',
  'hex'
);

function loadLicenseDbFromFile() {
  try {
    const buf = fs.readFileSync(LICENSE_DB_PATH, 'utf8');
    const parsed = JSON.parse(buf);
    if (!parsed.devices) parsed.devices = {};
    if (!parsed.issues) parsed.issues = [];
    return parsed;
  } catch (e) {
    return { devices: {}, issues: [] };
  }
}

function loadLicenseDb() {
  if (storageMode === 'github' && githubDbCache) {
    return githubDbCache;
  }
  if (storageMode === 'postgres' && pgPool && pgDbCache) {
    return pgDbCache;
  }
  return loadLicenseDbFromFile();
}

function saveLicenseDb(db) {
  if (storageMode === 'github') {
    githubDbCache = db;
    githubQueuePersist();
    return;
  }
  if (storageMode === 'postgres' && pgPool) {
    pgDbCache = db;
    pgPool
      .query('UPDATE license_state SET data = $1::jsonb WHERE id = 1', [JSON.stringify(db)])
      .catch((e) => console.error('License DB persist failed:', e));
    return;
  }
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  fs.writeFileSync(LICENSE_DB_PATH, JSON.stringify(db, null, 2), 'utf8');
}

/** 편집 API용: 저장이 끝날 때까지 대기 (GitHub 커밋 포함) */
async function saveLicenseDbAsync(db) {
  if (storageMode === 'github') {
    githubDbCache = db;
    githubQueuePersist();
    await githubSaveChain;
    return;
  }
  if (storageMode === 'postgres' && pgPool) {
    pgDbCache = db;
    await pgPool.query('UPDATE license_state SET data = $1::jsonb WHERE id = 1', [
      JSON.stringify(db),
    ]);
    return;
  }
  saveLicenseDb(db);
}

function escHtml(s) {
  return String(s == null ? '' : s)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function adminTokenExpected() {
  return (process.env.LICENSE_ADMIN_TOKEN || '').trim();
}

function checkAdminAuth(req) {
  const expected = adminTokenExpected();
  if (!expected) return true;
  const got =
    (req.headers['x-admin-token'] || '').trim() ||
    (() => {
      try {
        const u = new URL(req.url || '/', 'http://localhost');
        return (u.searchParams.get('token') || '').trim();
      } catch {
        return '';
      }
    })();
  return got === expected;
}

function sendJson(res, status, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
  });
  res.end(body);
}

function normalizeDeviceIdParam(raw) {
  const id = String(raw || '')
    .trim()
    .toLowerCase()
    .replace(/[^0-9a-f]/g, '');
  return /^[0-9a-f]{32}$/.test(id) ? id : null;
}

async function initLicenseStorage() {
  const ghToken = (process.env.LICENSE_GITHUB_TOKEN || '').trim();
  let ghRepo = (process.env.LICENSE_GITHUB_REPO || '').trim();
  if (ghToken) {
    if (!ghRepo) {
      ghRepo = DEFAULT_LICENSE_GITHUB_REPO;
    }
    const parts = ghRepo.split('/').filter(Boolean);
    if (parts.length !== 2) {
      throw new Error('LICENSE_GITHUB_REPO must be "owner/repo"');
    }
    [githubOwner, githubRepo] = parts;
    githubToken = ghToken;
    githubPath = (process.env.LICENSE_GITHUB_PATH || 'data/licenses.json').replace(/^\//, '');
    githubBranch = (process.env.LICENSE_GITHUB_BRANCH || 'main').trim();
    storageMode = 'github';
    await githubLoadInitial();
    console.log(
      `License DB: GitHub ${githubOwner}/${githubRepo}@${githubBranch}:${githubPath}`
    );
    return;
  }

  if (process.env.DATABASE_URL) {
    const { Pool } = require('pg');
    const ssl =
      process.env.DATABASE_SSL === '0'
        ? false
        : { rejectUnauthorized: false };
    pgPool = new Pool({
      connectionString: process.env.DATABASE_URL,
      max: 5,
      ssl,
    });
    await pgPool.query(`
      CREATE TABLE IF NOT EXISTS license_state (
        id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
        data JSONB NOT NULL
      );
    `);
    const r = await pgPool.query('SELECT data FROM license_state WHERE id = 1');
    if (r.rows.length === 0) {
      pgDbCache = { devices: {}, issues: [] };
      await pgPool.query('INSERT INTO license_state (id, data) VALUES (1, $1::jsonb)', [
        JSON.stringify(pgDbCache),
      ]);
    } else {
      let row = r.rows[0].data;
      if (typeof row === 'string') {
        row = JSON.parse(row);
      }
      if (!row.devices) row.devices = {};
      if (!row.issues) row.issues = [];
      pgDbCache = row;
    }
    storageMode = 'postgres';
    console.log('License DB: PostgreSQL (persistent across restarts)');
    return;
  }

  storageMode = 'file';
  console.log('License DB: JSON file', LICENSE_DB_PATH);
  console.log(
    'Hint: on Render free tier, set LICENSE_GITHUB_TOKEN + LICENSE_GITHUB_REPO, or DATABASE_URL.'
  );
}

function logLicenseIssue(deviceIdBuf, licenseBuf, signatureBuf, companyFromClient) {
  const deviceIdHex = deviceIdBuf.toString('hex');
  const nowIso = new Date().toISOString();

  const db = loadLicenseDb();
  if (!db.devices) db.devices = {};
  if (!db.issues) db.issues = [];

  if (!db.devices[deviceIdHex]) {
    db.devices[deviceIdHex] = {
      deviceId: deviceIdHex,
      company: companyFromClient || 'Unknown',
      firstSeenAt: nowIso,
      lastSeenAt: nowIso,
      issueCount: 1,
      lastSignature: signatureBuf.toString('hex')
    };
  } else {
    const rec = db.devices[deviceIdHex];
    if (companyFromClient) {
      rec.company = companyFromClient;
    }
    rec.lastSeenAt = nowIso;
    rec.issueCount = (rec.issueCount || 0) + 1;
    rec.lastSignature = signatureBuf.toString('hex');
    // note / updatedAt 은 웹 편집 값을 유지
  }

  // 전체 발급 이력에 한 건 추가
  db.issues.push({
    deviceId: deviceIdHex,
    company: companyFromClient || 'Unknown',
    issuedAt: nowIso,
  });

  saveLicenseDb(db);
}

function buildLicense(deviceIdBuf) {
  if (deviceIdBuf.length !== 16) {
    throw new Error('device_id must be 16 bytes');
  }

  // MAC 대상 메시지: ENCRYPTION_KEY(32) || device_id(16) => 48 bytes
  const macInput = Buffer.concat([MAC_KEY, deviceIdBuf]);
  // SHAKE256 출력 512비트(64바이트), hex 문자열로 받음
  const macHex = shake256(macInput, 512);
  const mac = Buffer.from(macHex, 'hex');
  if (mac.length !== 64) {
    throw new Error('invalid mac length');
  }

  const lic = Buffer.alloc(88);
  lic.write('SCRM', 0, 'ascii');  // magic
  lic.writeUInt8(1, 4);           // version
  // 5-7: reserved 0
  deviceIdBuf.copy(lic, 8);       // device_id
  mac.copy(lic, 24);              // MAC

  return lic;
}

/** TCP·HTTP 공통: JSON payload → 88바이트 라이선스 */
function issueLicenseFromPayload(payload) {
  const deviceIdHex = String(payload.deviceId || '').toLowerCase();
  const company = (payload.company || 'Unknown').toString();

  if (!/^[0-9a-f]{32}$/.test(deviceIdHex)) {
    throw new Error('invalid deviceId hex');
  }

  const deviceId = Buffer.from(deviceIdHex, 'hex');
  console.log('Received device_id:', deviceIdHex, 'company:', company);

  const license = buildLicense(deviceId);
  logLicenseIssue(deviceId, license, license.subarray(24, 24 + 64), company);
  return license;
}

function readHttpBody(req) {
  return new Promise((resolve, reject) => {
    const chunks = [];
    req.on('data', (c) => chunks.push(c));
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}

async function handleApiDevicesUpdate(req, res, deviceId) {
  if (!checkAdminAuth(req)) {
    sendJson(res, 401, { error: 'unauthorized' });
    return;
  }
  const body = await readHttpBody(req);
  let payload;
  try {
    payload = JSON.parse(body.toString('utf8') || '{}');
  } catch {
    sendJson(res, 400, { error: 'invalid JSON' });
    return;
  }

  const db = loadLicenseDb();
  if (!db.devices) db.devices = {};
  const rec = db.devices[deviceId];
  if (!rec) {
    sendJson(res, 404, { error: 'device not found' });
    return;
  }

  if (payload.company !== undefined) {
    const company = String(payload.company || '').trim() || 'Unknown';
    rec.company = company;
    // 같은 deviceId 발급 이력의 company 도 맞춤
    if (Array.isArray(db.issues)) {
      for (const iss of db.issues) {
        if (iss.deviceId === deviceId) iss.company = company;
      }
    }
  }
  if (payload.note !== undefined) {
    rec.note = String(payload.note || '').slice(0, 500);
  }
  rec.updatedAt = new Date().toISOString();
  db.devices[deviceId] = rec;

  await saveLicenseDbAsync(db);
  console.log('Device updated:', deviceId, 'company=', rec.company);
  sendJson(res, 200, { ok: true, device: rec });
}

async function handleApiDevicesDelete(req, res, deviceId) {
  if (!checkAdminAuth(req)) {
    sendJson(res, 401, { error: 'unauthorized' });
    return;
  }
  const db = loadLicenseDb();
  if (!db.devices || !db.devices[deviceId]) {
    sendJson(res, 404, { error: 'device not found' });
    return;
  }
  delete db.devices[deviceId];
  // 이력은 남겨 두되, 쿼리 ?purgeIssues=1 이면 함께 삭제
  let purge = false;
  try {
    const u = new URL(req.url || '/', 'http://localhost');
    purge = u.searchParams.get('purgeIssues') === '1';
  } catch {
    purge = false;
  }
  if (purge && Array.isArray(db.issues)) {
    db.issues = db.issues.filter((iss) => iss.deviceId !== deviceId);
  }
  await saveLicenseDbAsync(db);
  console.log('Device deleted:', deviceId, 'purgeIssues=', purge);
  sendJson(res, 200, { ok: true, deleted: deviceId, purgeIssues: purge });
}

/** Render/로컬 공통 HTTP 핸들러 */
function handleRenderHttp(req, res) {
  const urlPath = (req.url || '').split('?')[0];

  if (req.method === 'GET' && (urlPath === '/' || urlPath === '/index.html')) {
    const html = renderHtmlDashboard();
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
    return;
  }

  if (req.method === 'GET' && urlPath === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('ok');
    return;
  }

  if (req.method === 'GET' && urlPath === '/api/devices') {
    const db = loadLicenseDb();
    const devices = Object.values(db.devices || {}).sort((a, b) =>
      (a.firstSeenAt || '').localeCompare(b.firstSeenAt || '')
    );
    sendJson(res, 200, { storage: storageMode, devices, issueCount: (db.issues || []).length });
    return;
  }

  const deviceMatch = urlPath.match(/^\/api\/devices\/([0-9a-fA-F]+)$/);
  if (deviceMatch) {
    const deviceId = normalizeDeviceIdParam(deviceMatch[1]);
    if (!deviceId) {
      sendJson(res, 400, { error: 'invalid deviceId' });
      return;
    }
    if (req.method === 'PATCH' || req.method === 'PUT') {
      handleApiDevicesUpdate(req, res, deviceId).catch((e) => {
        console.error('PATCH device error:', e);
        sendJson(res, 500, { error: String(e.message || e) });
      });
      return;
    }
    if (req.method === 'DELETE') {
      handleApiDevicesDelete(req, res, deviceId).catch((e) => {
        console.error('DELETE device error:', e);
        sendJson(res, 500, { error: String(e.message || e) });
      });
      return;
    }
  }

  if (req.method === 'POST' && (urlPath === '/issue' || urlPath === '/license')) {
    readHttpBody(req)
      .then((body) => {
        try {
          const payload = JSON.parse(body.toString('utf8'));
          const license = issueLicenseFromPayload(payload);
          res.writeHead(200, {
            'Content-Type': 'application/octet-stream',
            'Content-Length': license.length,
          });
          res.end(license);
          console.log('License sent (HTTP, 88 bytes).');
        } catch (e) {
          console.error('HTTP /issue error:', e);
          res.writeHead(400, { 'Content-Type': 'text/plain; charset=utf-8' });
          res.end(String(e.message || e));
        }
      })
      .catch((e) => {
        console.error(e);
        res.writeHead(500, { 'Content-Type': 'text/plain; charset=utf-8' });
        res.end('internal error');
      });
    return;
  }

  res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
  res.end('Not Found');
}

// Render / PaaS: 공인 URL은 HTTP(S) 한 포트만. TCP 2000은 외부에 안 붙고,
// 로드밸런서가 보내는 HTTP가 TCP 소켓에 섞여 들어오면 JSON.parse 가 깨짐.
// RENDER_EXTERNAL_URL 은 Render가 항상 넣음. RENDER 는 문자열 "true".
const useUnifiedHttp =
  process.env.RENDER === 'true' ||
  process.env.RENDER === '1' ||
  Boolean(process.env.RENDER_EXTERNAL_URL) ||
  process.env.LICENSE_HTTP_UNIFIED === '1';

function startListeners() {
  if (useUnifiedHttp) {
    const port = Number(process.env.PORT) || 10000;
    const renderHttp = http.createServer(handleRenderHttp);
    renderHttp.listen(port, '0.0.0.0', () => {
      console.log(
        `Render mode: HTTP 0.0.0.0:${port}  GET /  GET /health  GET /api/devices  PATCH/DELETE /api/devices/:id  POST /issue`
      );
    });
  } else {
    const tcpServer = net.createServer((socket) => {
      console.log('Client connected from', socket.remoteAddress, socket.remotePort);

      let buf = Buffer.alloc(0);

      socket.on('data', (data) => {
        buf = Buffer.concat([buf, data]);
        const newlineIndex = buf.indexOf(0x0a); // '\n'
        if (newlineIndex === -1) {
          return;
        }

        const line = buf.slice(0, newlineIndex).toString('utf8').trim();

        try {
          const payload = JSON.parse(line);
          const license = issueLicenseFromPayload(payload);
          socket.write(license);
          socket.end();
          console.log('License sent (88 bytes).');
        } catch (e) {
          console.error('Error while handling request:', e);
          socket.destroy();
        }
      });

      socket.on('error', (err) => {
        console.error('Socket error:', err.message);
      });

      socket.on('end', () => {
        console.log('Client disconnected');
      });
    });

    tcpServer.listen(TCP_PORT, TCP_HOST, () => {
      console.log(`License TCP server listening on ${TCP_HOST}:${TCP_PORT}`);
    });

    const httpServer = http.createServer(handleRenderHttp);
    httpServer.listen(HTTP_PORT, HTTP_HOST, () => {
      console.log(
        `License HTTP dashboard listening on http://${HTTP_HOST}:${HTTP_PORT}/  (edit: PATCH /api/devices/:id)`
      );
    });
  }
}

// HTML 대시보드 (웹에서 회사명/메모 편집 · 삭제)
function renderHtmlDashboard() {
  const db = loadLicenseDb();
  const devices = Object.values(db.devices || {});
  const issues = db.issues || [];
  const adminRequired = adminTokenExpected() ? '1' : '0';

  const companyStats = {};
  for (const d of devices) {
    const company = d.company || 'Unknown';
    companyStats[company] = (companyStats[company] || 0) + 1;
  }

  const companyRows = Object.entries(companyStats)
    .sort((a, b) => b[1] - a[1])
    .map(
      ([company, count]) =>
        `<tr><td>${escHtml(company)}</td><td style="text-align:right">${count}</td></tr>`
    )
    .join('\n');

  const deviceRows = devices
    .sort((a, b) => (a.firstSeenAt || '').localeCompare(b.firstSeenAt || ''))
    .map((d) => {
      const id = escHtml(d.deviceId);
      const company = escHtml(d.company || 'Unknown');
      const note = escHtml(d.note || '');
      return `
        <tr data-id="${id}">
          <td><code class="dev-id">${id}</code></td>
          <td><input class="inp-company" type="text" value="${company}" maxlength="120" /></td>
          <td><input class="inp-note" type="text" value="${note}" maxlength="500" placeholder="메모" /></td>
          <td style="text-align:right">${d.issueCount || 0}</td>
          <td class="muted">${escHtml(d.firstSeenAt || '')}</td>
          <td class="muted">${escHtml(d.lastSeenAt || '')}</td>
          <td class="actions">
            <button type="button" class="btn-save">저장</button>
            <button type="button" class="btn-del danger">삭제</button>
          </td>
        </tr>`;
    })
    .join('\n');

  const issuesByCompany = {};
  for (const iss of issues) {
    const company = iss.company || 'Unknown';
    if (!issuesByCompany[company]) issuesByCompany[company] = [];
    issuesByCompany[company].push(iss);
  }

  const companyIssueSections = Object.entries(issuesByCompany)
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([company, companyIssues]) => {
      const rows = companyIssues
        .slice()
        .sort((a, b) => (a.issuedAt || '').localeCompare(b.issuedAt || ''))
        .map(
          (iss) => `
            <tr>
              <td>${escHtml(iss.issuedAt || '')}</td>
              <td><code>${escHtml(iss.deviceId)}</code></td>
            </tr>`
        )
        .join('\n');

      return `
        <h3>${escHtml(company)}</h3>
        <table>
          <thead><tr><th>발급 시간</th><th>Device ID</th></tr></thead>
          <tbody>${rows || '<tr><td colspan="2">발급 이력 없음</td></tr>'}</tbody>
        </table>`;
    })
    .join('\n');

  return `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Scream License Dashboard</title>
  <style>
    :root { --bg:#f5f7fb; --card:#fff; --line:#dde3ee; --ink:#1a1f2e; --muted:#667085; --accent:#1d4ed8; --danger:#b91c1c; --ok:#15803d; }
    * { box-sizing: border-box; }
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 0; padding: 24px; background: var(--bg); color: var(--ink); }
    h1 { margin: 0 0 8px; font-size: 1.5rem; }
    h2 { margin: 28px 0 10px; font-size: 1.1rem; }
    h3 { margin: 18px 0 8px; font-size: 1rem; }
    .meta { color: var(--muted); font-size: 13px; margin: 0 0 16px; }
    .toolbar { display:flex; flex-wrap:wrap; gap:10px; align-items:end; background:var(--card); border:1px solid var(--line); border-radius:10px; padding:14px; margin-bottom:18px; }
    .toolbar label { display:flex; flex-direction:column; gap:4px; font-size:12px; color:var(--muted); }
    .toolbar input { min-width:220px; padding:8px 10px; border:1px solid var(--line); border-radius:8px; font-size:13px; }
    .toolbar .hint { font-size:12px; color:var(--muted); flex:1; min-width:200px; }
    #status { min-height:1.2em; font-size:13px; margin: 0 0 12px; }
    #status.ok { color: var(--ok); }
    #status.err { color: var(--danger); }
    table { border-collapse: collapse; width: 100%; margin-bottom: 20px; background: var(--card); border-radius: 10px; overflow: hidden; }
    th, td { border: 1px solid var(--line); padding: 8px; font-size: 13px; vertical-align: middle; }
    th { background: #eef2f8; text-align: left; white-space: nowrap; }
    code, .dev-id { font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace; font-size: 11px; word-break: break-all; }
    .muted { color: var(--muted); font-size: 12px; white-space: nowrap; }
    input.inp-company, input.inp-note { width: 100%; min-width: 100px; padding: 6px 8px; border: 1px solid var(--line); border-radius: 6px; font-size: 13px; }
    .actions { white-space: nowrap; }
    button { cursor: pointer; border: 1px solid var(--line); background: #fff; border-radius: 6px; padding: 6px 10px; font-size: 12px; }
    button:hover { background: #f8fafc; }
    button.btn-save { border-color: #93c5fd; color: var(--accent); font-weight: 600; }
    button.danger { border-color: #fecaca; color: var(--danger); }
    .hidden { display: none !important; }
  </style>
</head>
<body data-admin-required="${adminRequired}">
  <h1>Scream License Dashboard</h1>
  <p class="meta">총 디바이스 ${devices.length} · 발급 이력 ${issues.length} · 저장: ${escHtml(storageMode)}</p>

  <div class="toolbar ${adminRequired === '1' ? '' : 'hidden'}" id="adminBar">
    <label>관리 토큰 (LICENSE_ADMIN_TOKEN)
      <input id="adminToken" type="password" autocomplete="off" placeholder="편집 시 필요" />
    </label>
    <p class="hint">Render Environment 에 설정한 토큰을 입력하면 회사명·메모 수정/삭제가 가능합니다. 브라우저에만 저장됩니다.</p>
  </div>
  <div id="status"></div>

  <h2>회사별 디바이스 수</h2>
  <table>
    <thead><tr><th>회사</th><th>디바이스 수</th></tr></thead>
    <tbody>${companyRows || '<tr><td colspan="2">데이터 없음</td></tr>'}</tbody>
  </table>

  <h2>디바이스별 라이선스 정보 (편집 가능)</h2>
  <table>
    <thead>
      <tr>
        <th>Device ID</th>
        <th>회사</th>
        <th>메모</th>
        <th>발급 횟수</th>
        <th>최초 발급</th>
        <th>마지막 발급</th>
        <th>동작</th>
      </tr>
    </thead>
    <tbody id="deviceTable">
      ${deviceRows || '<tr><td colspan="7">데이터 없음</td></tr>'}
    </tbody>
  </table>

  <h2>회사별 발급 이력</h2>
  ${companyIssueSections || '<p class="meta">발급 이력이 없습니다.</p>'}

  <p class="meta">회사명·메모는 「저장」으로 반영됩니다. 삭제 시 디바이스 목록에서만 제거되며, 발급 이력은 기본 유지됩니다.</p>

  <script>
    (function () {
      const adminRequired = document.body.dataset.adminRequired === '1';
      const tokenInput = document.getElementById('adminToken');
      const statusEl = document.getElementById('status');
      const KEY = 'scream_license_admin_token';

      if (adminRequired && tokenInput) {
        tokenInput.value = sessionStorage.getItem(KEY) || '';
        tokenInput.addEventListener('change', function () {
          sessionStorage.setItem(KEY, tokenInput.value || '');
        });
      }

      function setStatus(msg, ok) {
        statusEl.textContent = msg || '';
        statusEl.className = ok === true ? 'ok' : ok === false ? 'err' : '';
      }

      function headers() {
        const h = { 'Content-Type': 'application/json', 'Accept': 'application/json' };
        if (adminRequired && tokenInput && tokenInput.value) {
          h['X-Admin-Token'] = tokenInput.value;
        }
        return h;
      }

      async function saveRow(tr) {
        const id = tr.getAttribute('data-id');
        const company = tr.querySelector('.inp-company').value.trim();
        const note = tr.querySelector('.inp-note').value;
        setStatus('저장 중…');
        try {
          const res = await fetch('/api/devices/' + encodeURIComponent(id), {
            method: 'PATCH',
            headers: headers(),
            body: JSON.stringify({ company: company || 'Unknown', note: note }),
          });
          const data = await res.json().catch(function () { return {}; });
          if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
          setStatus('저장 완료: ' + id.slice(0, 8) + '…', true);
          setTimeout(function () { location.reload(); }, 500);
        } catch (e) {
          setStatus('저장 실패: ' + e.message, false);
        }
      }

      async function deleteRow(tr) {
        const id = tr.getAttribute('data-id');
        if (!confirm('이 디바이스 기록을 삭제할까요?\\n' + id)) return;
        const purge = confirm('발급 이력까지 함께 삭제할까요?\\n(취소하면 디바이스 목록만 제거)');
        setStatus('삭제 중…');
        try {
          const url = '/api/devices/' + encodeURIComponent(id) + (purge ? '?purgeIssues=1' : '');
          const res = await fetch(url, { method: 'DELETE', headers: headers() });
          const data = await res.json().catch(function () { return {}; });
          if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
          setStatus('삭제 완료', true);
          setTimeout(function () { location.reload(); }, 400);
        } catch (e) {
          setStatus('삭제 실패: ' + e.message, false);
        }
      }

      document.getElementById('deviceTable').addEventListener('click', function (ev) {
        const t = ev.target;
        const tr = t.closest('tr[data-id]');
        if (!tr) return;
        if (t.classList.contains('btn-save')) saveRow(tr);
        if (t.classList.contains('btn-del')) deleteRow(tr);
      });
    })();
  </script>
</body>
</html>`;
}

initLicenseStorage()
  .then(() => {
    startListeners();
  })
  .catch((err) => {
    console.error('initLicenseStorage failed:', err);
    process.exit(1);
  });

