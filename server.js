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
    if (!parsed.companies) parsed.companies = {};
    githubDbCache = parsed;
  } catch (e) {
    if (e.status === 404) {
      githubDbCache = { devices: {}, issues: [], companies: {} };
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
    if (!parsed.companies) parsed.companies = {};
    return parsed;
  } catch (e) {
    return { devices: {}, issues: [], companies: {} };
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
      pgDbCache = { devices: {}, issues: [], companies: {} };
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
      if (!row.companies) row.companies = {};
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

function normalizeCompanyName(name) {
  const s = String(name == null ? '' : name).trim();
  return s || 'Unknown';
}

/** ISO / 'YYYY-MM-DD HH:mm'(KST) / Date 문자열 → ISO */
function parseFlexibleDate(value) {
  if (value == null || String(value).trim() === '') return null;
  const t = String(value).trim();
  let d;
  if (/^\d{4}-\d{2}-\d{2}T/.test(t)) {
    d = new Date(t);
  } else if (/^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}(:\d{2})?$/.test(t)) {
    const norm = t.replace(' ', 'T');
    const withSec = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}$/.test(norm) ? `${norm}:00` : norm;
    d = new Date(`${withSec}+09:00`);
  } else {
    d = new Date(t);
  }
  if (Number.isNaN(d.getTime())) return null;
  return d.toISOString();
}

function formatInputKst(iso) {
  if (!iso) return '';
  const formatted = formatKst(iso);
  // formatKst: "2026. 04. 02. 14:25" or similar — rebuild YYYY-MM-DD HH:mm
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  try {
    const parts = new Intl.DateTimeFormat('en-CA', {
      timeZone: 'Asia/Seoul',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }).formatToParts(d);
    const get = (type) => {
      const p = parts.find((x) => x.type === type);
      return p ? p.value : '';
    };
    let hour = get('hour');
    if (hour === '24') hour = '00';
    return `${get('year')}-${get('month')}-${get('day')} ${hour}:${get('minute')}`;
  } catch (_) {
    return formatted;
  }
}

async function readJsonBody(req) {
  const body = await readHttpBody(req);
  try {
    return JSON.parse(body.toString('utf8') || '{}');
  } catch {
    const err = new Error('invalid JSON');
    err.status = 400;
    throw err;
  }
}

async function handleApiDevicesUpdate(req, res, deviceId) {
  if (!checkAdminAuth(req)) {
    sendJson(res, 401, { error: 'unauthorized' });
    return;
  }
  let payload;
  try {
    payload = await readJsonBody(req);
  } catch (e) {
    sendJson(res, 400, { error: String(e.message || e) });
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
    const company = normalizeCompanyName(payload.company);
    rec.company = company;
    if (Array.isArray(db.issues)) {
      for (const iss of db.issues) {
        if (iss.deviceId === deviceId) iss.company = company;
      }
    }
  }
  if (payload.note !== undefined) {
    rec.note = String(payload.note || '').slice(0, 500);
  }
  if (payload.issueCount !== undefined) {
    const n = Number(payload.issueCount);
    if (!Number.isFinite(n) || n < 0) {
      sendJson(res, 400, { error: 'invalid issueCount' });
      return;
    }
    rec.issueCount = Math.floor(n);
  }
  if (payload.firstSeenAt !== undefined) {
    const iso = parseFlexibleDate(payload.firstSeenAt);
    if (payload.firstSeenAt && !iso) {
      sendJson(res, 400, { error: 'invalid firstSeenAt' });
      return;
    }
    rec.firstSeenAt = iso || '';
  }
  if (payload.lastSeenAt !== undefined) {
    const iso = parseFlexibleDate(payload.lastSeenAt);
    if (payload.lastSeenAt && !iso) {
      sendJson(res, 400, { error: 'invalid lastSeenAt' });
      return;
    }
    rec.lastSeenAt = iso || '';
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

/** 회사명 일괄 변경 + 회사 메모 저장 */
async function handleApiCompaniesUpdate(req, res) {
  if (!checkAdminAuth(req)) {
    sendJson(res, 401, { error: 'unauthorized' });
    return;
  }
  let payload;
  try {
    payload = await readJsonBody(req);
  } catch (e) {
    sendJson(res, 400, { error: String(e.message || e) });
    return;
  }

  const from = normalizeCompanyName(payload.from);
  const to = payload.to !== undefined ? normalizeCompanyName(payload.to) : from;
  const db = loadLicenseDb();
  if (!db.devices) db.devices = {};
  if (!db.issues) db.issues = [];
  if (!db.companies) db.companies = {};

  let deviceHits = 0;
  let issueHits = 0;
  for (const id of Object.keys(db.devices)) {
    const rec = db.devices[id];
    if (normalizeCompanyName(rec.company) === from) {
      rec.company = to;
      rec.updatedAt = new Date().toISOString();
      deviceHits += 1;
    }
  }
  for (const iss of db.issues) {
    if (normalizeCompanyName(iss.company) === from) {
      iss.company = to;
      issueHits += 1;
    }
  }

  const meta = db.companies[from] || db.companies[to] || {};
  if (from !== to && db.companies[from]) {
    delete db.companies[from];
  }
  db.companies[to] = {
    name: to,
    note: payload.note !== undefined ? String(payload.note || '').slice(0, 500) : meta.note || '',
    contact:
      payload.contact !== undefined
        ? String(payload.contact || '').slice(0, 200)
        : meta.contact || '',
    updatedAt: new Date().toISOString(),
  };

  if (deviceHits === 0 && issueHits === 0 && payload.note === undefined && payload.contact === undefined) {
    sendJson(res, 404, { error: 'company not found', from });
    return;
  }

  await saveLicenseDbAsync(db);
  console.log('Company updated:', from, '->', to, 'devices=', deviceHits, 'issues=', issueHits);
  sendJson(res, 200, {
    ok: true,
    from,
    to,
    deviceHits,
    issueHits,
    company: db.companies[to],
  });
}

/** 회사 소속 디바이스/이력 일괄 삭제 */
async function handleApiCompaniesDelete(req, res) {
  if (!checkAdminAuth(req)) {
    sendJson(res, 401, { error: 'unauthorized' });
    return;
  }
  let payload;
  try {
    payload = await readJsonBody(req);
  } catch (e) {
    sendJson(res, 400, { error: String(e.message || e) });
    return;
  }
  const name = normalizeCompanyName(payload.name || payload.company);
  const purgeDevices = payload.purgeDevices !== false;
  const purgeIssues = payload.purgeIssues !== false;
  const db = loadLicenseDb();
  if (!db.devices) db.devices = {};
  if (!db.issues) db.issues = [];
  if (!db.companies) db.companies = {};

  let deletedDevices = 0;
  if (purgeDevices) {
    for (const id of Object.keys(db.devices)) {
      if (normalizeCompanyName(db.devices[id].company) === name) {
        delete db.devices[id];
        deletedDevices += 1;
      }
    }
  }
  let deletedIssues = 0;
  if (purgeIssues) {
    const before = db.issues.length;
    db.issues = db.issues.filter((iss) => normalizeCompanyName(iss.company) !== name);
    deletedIssues = before - db.issues.length;
  }
  if (db.companies[name]) delete db.companies[name];

  await saveLicenseDbAsync(db);
  console.log('Company deleted:', name, 'devices=', deletedDevices, 'issues=', deletedIssues);
  sendJson(res, 200, { ok: true, name, deletedDevices, deletedIssues });
}

function findIssueIndex(db, match) {
  if (!match || !Array.isArray(db.issues)) return -1;
  const deviceId = String(match.deviceId || '').toLowerCase();
  const issuedAt = String(match.issuedAt || '');
  return db.issues.findIndex(
    (iss) => String(iss.deviceId || '').toLowerCase() === deviceId && String(iss.issuedAt || '') === issuedAt
  );
}

/** 발급 이력 1건 수정 */
async function handleApiIssuesUpdate(req, res) {
  if (!checkAdminAuth(req)) {
    sendJson(res, 401, { error: 'unauthorized' });
    return;
  }
  let payload;
  try {
    payload = await readJsonBody(req);
  } catch (e) {
    sendJson(res, 400, { error: String(e.message || e) });
    return;
  }
  const db = loadLicenseDb();
  if (!db.issues) db.issues = [];
  const idx = findIssueIndex(db, payload.match || payload);
  if (idx < 0) {
    sendJson(res, 404, { error: 'issue not found' });
    return;
  }
  const iss = db.issues[idx];
  if (payload.company !== undefined) {
    iss.company = normalizeCompanyName(payload.company);
  }
  if (payload.issuedAt !== undefined) {
    const iso = parseFlexibleDate(payload.issuedAt);
    if (!iso) {
      sendJson(res, 400, { error: 'invalid issuedAt' });
      return;
    }
    iss.issuedAt = iso;
  }
  if (payload.deviceId !== undefined) {
    const id = normalizeDeviceIdParam(payload.deviceId);
    if (!id) {
      sendJson(res, 400, { error: 'invalid deviceId' });
      return;
    }
    iss.deviceId = id;
  }
  db.issues[idx] = iss;
  await saveLicenseDbAsync(db);
  console.log('Issue updated:', iss.deviceId, iss.issuedAt);
  sendJson(res, 200, { ok: true, issue: iss });
}

async function handleApiIssuesDelete(req, res) {
  if (!checkAdminAuth(req)) {
    sendJson(res, 401, { error: 'unauthorized' });
    return;
  }
  let payload;
  try {
    payload = await readJsonBody(req);
  } catch (e) {
    sendJson(res, 400, { error: String(e.message || e) });
    return;
  }
  const db = loadLicenseDb();
  if (!db.issues) db.issues = [];
  const idx = findIssueIndex(db, payload.match || payload);
  if (idx < 0) {
    sendJson(res, 404, { error: 'issue not found' });
    return;
  }
  const removed = db.issues.splice(idx, 1)[0];
  await saveLicenseDbAsync(db);
  console.log('Issue deleted:', removed.deviceId, removed.issuedAt);
  sendJson(res, 200, { ok: true, deleted: removed });
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

  if (urlPath === '/api/companies') {
    if (req.method === 'PATCH' || req.method === 'PUT') {
      handleApiCompaniesUpdate(req, res).catch((e) => {
        console.error('PATCH company error:', e);
        sendJson(res, 500, { error: String(e.message || e) });
      });
      return;
    }
    if (req.method === 'DELETE') {
      handleApiCompaniesDelete(req, res).catch((e) => {
        console.error('DELETE company error:', e);
        sendJson(res, 500, { error: String(e.message || e) });
      });
      return;
    }
  }

  if (urlPath === '/api/issues') {
    if (req.method === 'PATCH' || req.method === 'PUT') {
      handleApiIssuesUpdate(req, res).catch((e) => {
        console.error('PATCH issue error:', e);
        sendJson(res, 500, { error: String(e.message || e) });
      });
      return;
    }
    if (req.method === 'DELETE') {
      handleApiIssuesDelete(req, res).catch((e) => {
        console.error('DELETE issue error:', e);
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

function formatKst(iso) {
  if (!iso) return '-';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return String(iso);
  try {
    return new Intl.DateTimeFormat('ko-KR', {
      timeZone: 'Asia/Seoul',
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
      hour12: false,
    }).format(d);
  } catch (_) {
    return d.toISOString().replace('T', ' ').slice(0, 16);
  }
}

function shortId(hex) {
  const s = String(hex || '');
  if (s.length <= 12) return s;
  return s.slice(0, 6) + '…' + s.slice(-6);
}

function daysAgoIso(iso) {
  if (!iso) return null;
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return null;
  return Math.floor((Date.now() - t) / 86400000);
}

// HTML 대시보드 — 담당자 한눈 요약 + 검색/필터 + 편집
function renderHtmlDashboard() {
  const db = loadLicenseDb();
  const devices = Object.values(db.devices || {});
  const issues = db.issues || [];
  const adminRequired = adminTokenExpected() ? '1' : '0';
  const nowIso = new Date().toISOString();

  const companyMeta = db.companies || {};
  const companyMap = {};
  let unknownCount = 0;
  let reissueCount = 0;
  for (const d of devices) {
    const company = normalizeCompanyName(d.company);
    if (!companyMap[company]) {
      const meta = companyMeta[company] || {};
      companyMap[company] = {
        company,
        devices: 0,
        issues: 0,
        lastSeenAt: '',
        note: meta.note || '',
        contact: meta.contact || '',
      };
    }
    companyMap[company].devices += 1;
    if (!companyMap[company].lastSeenAt || (d.lastSeenAt || '') > companyMap[company].lastSeenAt) {
      companyMap[company].lastSeenAt = d.lastSeenAt || '';
    }
    if (company === 'Unknown') unknownCount += 1;
    if ((d.issueCount || 0) > 1) reissueCount += 1;
  }
  for (const iss of issues) {
    const company = normalizeCompanyName(iss.company);
    if (!companyMap[company]) {
      const meta = companyMeta[company] || {};
      companyMap[company] = {
        company,
        devices: 0,
        issues: 0,
        lastSeenAt: '',
        note: meta.note || '',
        contact: meta.contact || '',
      };
    }
    companyMap[company].issues += 1;
  }
  // 메타만 있고 디바이스/이력이 없는 회사도 표시
  for (const name of Object.keys(companyMeta)) {
    const company = normalizeCompanyName(name);
    if (!companyMap[company]) {
      const meta = companyMeta[name] || {};
      companyMap[company] = {
        company,
        devices: 0,
        issues: 0,
        lastSeenAt: '',
        note: meta.note || '',
        contact: meta.contact || '',
      };
    }
  }

  const companies = Object.values(companyMap).sort((a, b) => b.devices - a.devices);
  const recentIssues = issues
    .slice()
    .sort((a, b) => (b.issuedAt || '').localeCompare(a.issuedAt || ''))
    .slice(0, 8);
  const recent7d = issues.filter((iss) => {
    const days = daysAgoIso(iss.issuedAt);
    return days != null && days <= 7;
  }).length;
  const lastIssueAt = recentIssues[0] ? recentIssues[0].issuedAt : '';

  const companyChips = companies
    .map(
      (c) =>
        `<button type="button" class="chip" data-filter-company="${escHtml(c.company)}">${escHtml(
          c.company
        )} <span>${c.devices}</span></button>`
    )
    .join('');

  const companyCards = companies
    .map((c) => {
      const warn = c.company === 'Unknown' ? ' warn' : '';
      return `<article class="co-card${warn}" data-company="${escHtml(c.company)}">
        <div class="co-name">${escHtml(c.company)}</div>
        <div class="co-nums"><b>${c.devices}</b>대 · 발급 ${c.issues}회</div>
        <div class="co-sub">최근 ${escHtml(formatKst(c.lastSeenAt))}</div>
        ${c.note ? `<div class="co-sub">${escHtml(c.note)}</div>` : ''}
      </article>`;
    })
    .join('');

  const companyRows = companies
    .map((c) => {
      return `<tr class="co-row" data-from="${escHtml(c.company)}">
        <td><input class="inp-co-name" type="text" value="${escHtml(c.company)}" maxlength="120" /></td>
        <td><input class="inp-co-note" type="text" value="${escHtml(c.note || '')}" maxlength="500" placeholder="회사 메모" /></td>
        <td><input class="inp-co-contact" type="text" value="${escHtml(c.contact || '')}" maxlength="200" placeholder="담당/연락처" /></td>
        <td class="num">${c.devices}</td>
        <td class="num">${c.issues}</td>
        <td class="muted">${escHtml(formatKst(c.lastSeenAt))}</td>
        <td class="actions">
          <button type="button" class="btn-co-save">저장</button>
          <button type="button" class="btn-co-del danger">삭제</button>
        </td>
      </tr>`;
    })
    .join('');

  const deviceRows = devices
    .slice()
    .sort((a, b) => (b.lastSeenAt || '').localeCompare(a.lastSeenAt || ''))
    .map((d) => {
      const id = d.deviceId || '';
      const company = normalizeCompanyName(d.company);
      const note = d.note || '';
      const unknown = company === 'Unknown' ? '1' : '0';
      const searchBlob = escHtml(
        [id, company, note, formatKst(d.firstSeenAt), formatKst(d.lastSeenAt)].join(' ').toLowerCase()
      );
      return `<tr class="dev-row" data-id="${escHtml(id)}" data-company="${escHtml(
        company
      )}" data-unknown="${unknown}" data-search="${searchBlob}">
        <td>
          <div class="id-wrap">
            <code class="id-short" title="${escHtml(id)}">${escHtml(shortId(id))}</code>
            <button type="button" class="btn-copy" data-copy="${escHtml(id)}" title="전체 ID 복사">복사</button>
          </div>
          <div class="id-full muted">${escHtml(id)}</div>
        </td>
        <td><input class="inp-company" type="text" value="${escHtml(company)}" maxlength="120" /></td>
        <td><input class="inp-note" type="text" value="${escHtml(note)}" maxlength="500" placeholder="설치 위치·담당자 등" /></td>
        <td><input class="inp-count num" type="number" min="0" step="1" value="${Number(d.issueCount || 0)}" /></td>
        <td><input class="inp-first" type="text" value="${escHtml(formatInputKst(d.firstSeenAt))}" placeholder="YYYY-MM-DD HH:mm" /></td>
        <td><input class="inp-last" type="text" value="${escHtml(formatInputKst(d.lastSeenAt))}" placeholder="YYYY-MM-DD HH:mm" /></td>
        <td class="actions">
          <button type="button" class="btn-save">저장</button>
          <button type="button" class="btn-del danger">삭제</button>
        </td>
      </tr>`;
    })
    .join('');

  const recentRows = recentIssues
    .map(
      (iss) => `<tr>
        <td>${escHtml(formatKst(iss.issuedAt))}</td>
        <td>${escHtml(iss.company || 'Unknown')}</td>
        <td><code title="${escHtml(iss.deviceId)}">${escHtml(shortId(iss.deviceId))}</code></td>
      </tr>`
    )
    .join('');

  const historySections = companies
    .map((c) => {
      const companyIssues = issues
        .filter((iss) => normalizeCompanyName(iss.company) === c.company)
        .sort((a, b) => (b.issuedAt || '').localeCompare(a.issuedAt || ''));
      const rows = companyIssues
        .map((iss) => {
          const matchId = escHtml(iss.deviceId || '');
          const matchAt = escHtml(iss.issuedAt || '');
          return `<tr class="iss-row" data-device="${matchId}" data-issued="${matchAt}">
            <td><input class="inp-iss-at" type="text" value="${escHtml(formatInputKst(iss.issuedAt))}" placeholder="YYYY-MM-DD HH:mm" /></td>
            <td><input class="inp-iss-company" type="text" value="${escHtml(
              normalizeCompanyName(iss.company)
            )}" maxlength="120" /></td>
            <td><input class="inp-iss-device" type="text" value="${matchId}" maxlength="32" /></td>
            <td class="actions">
              <button type="button" class="btn-iss-save">저장</button>
              <button type="button" class="btn-iss-del danger">삭제</button>
            </td>
          </tr>`;
        })
        .join('');
      return `<details class="hist-block" data-company="${escHtml(c.company)}" open>
        <summary><strong>${escHtml(c.company)}</strong> <span class="muted">${companyIssues.length}건 / 디바이스 ${c.devices}대</span></summary>
        <table>
          <thead><tr><th>발급 시각 (KST)</th><th>회사</th><th>Device ID</th><th>동작</th></tr></thead>
          <tbody class="issueTable">${rows || '<tr><td colspan="4">이력 없음</td></tr>'}</tbody>
        </table>
      </details>`;
    })
    .join('');

  return `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Scream 라이선스 현황</title>
  <style>
    :root {
      --bg: #eef2f0;
      --ink: #14201c;
      --muted: #5b6b64;
      --card: #ffffff;
      --line: #d5ddd8;
      --accent: #0f6b4c;
      --accent-soft: #e3f2eb;
      --warn: #9a6700;
      --warn-bg: #fff7e6;
      --danger: #b42318;
      --ok: #067647;
      --shadow: 0 1px 2px rgba(20,32,28,.06), 0 8px 24px rgba(20,32,28,.06);
      --radius: 14px;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; color: var(--ink);
      font-family: "Pretendard", "Noto Sans KR", "Apple SD Gothic Neo", sans-serif;
      background:
        radial-gradient(1200px 500px at 10% -10%, #d9ebe2 0%, transparent 55%),
        radial-gradient(900px 400px at 100% 0%, #e7efe9 0%, transparent 50%),
        var(--bg);
      min-height: 100vh;
    }
    .wrap { max-width: 1180px; margin: 0 auto; padding: 20px 16px 48px; }
    header.app {
      display: flex; flex-wrap: wrap; gap: 14px; justify-content: space-between; align-items: flex-end;
      margin-bottom: 18px;
    }
    .brand h1 { margin: 0; font-size: 1.55rem; letter-spacing: -0.02em; }
    .brand p { margin: 6px 0 0; color: var(--muted); font-size: 13px; }
    .badge {
      display: inline-flex; align-items: center; gap: 6px;
      background: var(--card); border: 1px solid var(--line); border-radius: 999px;
      padding: 6px 12px; font-size: 12px; color: var(--muted); box-shadow: var(--shadow);
    }
    .badge b { color: var(--accent); font-weight: 700; }
    .kpis { display: grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap: 10px; margin-bottom: 16px; }
    .kpi {
      background: var(--card); border: 1px solid var(--line); border-radius: var(--radius);
      padding: 14px 14px 12px; box-shadow: var(--shadow); min-height: 92px;
    }
    .kpi.warn { background: var(--warn-bg); border-color: #f0d79a; }
    .kpi .label { font-size: 12px; color: var(--muted); margin-bottom: 8px; }
    .kpi .value { font-size: 1.7rem; font-weight: 750; letter-spacing: -0.03em; line-height: 1.1; }
    .kpi .sub { margin-top: 6px; font-size: 11px; color: var(--muted); }
    .panel {
      background: var(--card); border: 1px solid var(--line); border-radius: var(--radius);
      box-shadow: var(--shadow); padding: 16px; margin-bottom: 14px;
    }
    .panel h2 { margin: 0 0 12px; font-size: 1.05rem; }
    .panel-head { display:flex; flex-wrap:wrap; gap:10px; justify-content:space-between; align-items:center; margin-bottom:12px; }
    .panel-head h2 { margin: 0; }
    .nav { display:flex; gap:6px; flex-wrap:wrap; margin-bottom: 14px; }
    .nav button {
      border: 1px solid var(--line); background: #fff; color: var(--muted);
      border-radius: 999px; padding: 8px 14px; font-size: 13px; cursor: pointer;
    }
    .nav button.active { background: var(--accent); border-color: var(--accent); color: #fff; font-weight: 650; }
    .hidden { display: none !important; }
    .co-grid { display:grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap: 10px; }
    .co-card {
      border: 1px solid var(--line); border-radius: 12px; padding: 12px; background: #fbfcfb;
      cursor: pointer; transition: border-color .15s, transform .15s;
    }
    .co-card:hover { border-color: #9fbfaf; transform: translateY(-1px); }
    .co-card.warn { background: var(--warn-bg); }
    .co-name { font-weight: 700; margin-bottom: 6px; }
    .co-nums { font-size: 13px; }
    .co-sub { margin-top: 6px; font-size: 11px; color: var(--muted); }
    .filters { display:flex; flex-wrap:wrap; gap:8px; align-items:center; margin-bottom: 12px; }
    .filters input, .filters select {
      border: 1px solid var(--line); border-radius: 10px; padding: 9px 11px; font-size: 13px; background:#fff;
    }
    .filters input[type="search"] { flex: 1; min-width: 180px; }
    .chips { display:flex; flex-wrap:wrap; gap:6px; margin-bottom: 10px; }
    .chip {
      border: 1px solid var(--line); background: #f7faf8; border-radius: 999px;
      padding: 5px 10px; font-size: 12px; cursor: pointer; color: var(--ink);
    }
    .chip span { color: var(--accent); font-weight: 700; margin-left: 4px; }
    .chip.active { background: var(--accent-soft); border-color: #8fbfa4; }
    table { width: 100%; border-collapse: collapse; }
    th, td { border-bottom: 1px solid var(--line); padding: 9px 8px; font-size: 13px; text-align: left; vertical-align: middle; }
    th { font-size: 12px; color: var(--muted); font-weight: 650; background: #f6f9f7; position: sticky; top: 0; }
    .table-scroll { overflow: auto; max-height: min(62vh, 720px); border: 1px solid var(--line); border-radius: 12px; }
    .num { text-align: right; font-variant-numeric: tabular-nums; }
    .muted { color: var(--muted); font-size: 12px; }
    code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 11px; }
    .id-wrap { display:flex; gap:6px; align-items:center; }
    .id-full { margin-top: 3px; word-break: break-all; }
    input.inp-company, input.inp-note, input.inp-co-name, input.inp-co-note, input.inp-co-contact,
    input.inp-first, input.inp-last, input.inp-iss-at, input.inp-iss-company, input.inp-iss-device, input.inp-count {
      width: 100%; min-width: 90px; border: 1px solid var(--line); border-radius: 8px;
      padding: 7px 8px; font-size: 13px; background: #fff;
    }
    input.inp-count { min-width: 64px; max-width: 88px; }
    .actions { white-space: nowrap; }
    button {
      cursor: pointer; border: 1px solid var(--line); background: #fff;
      border-radius: 8px; padding: 6px 10px; font-size: 12px;
    }
    button:hover { background: #f4f7f5; }
    .btn-save { border-color: #9fbfaf; color: var(--accent); font-weight: 700; }
    .danger { border-color: #f3b0aa; color: var(--danger); }
    .btn-copy { padding: 3px 7px; font-size: 11px; }
    .toolbar {
      display:flex; flex-wrap:wrap; gap:10px; align-items:end;
      background: #f7faf8; border: 1px dashed #b7c9be; border-radius: 12px; padding: 12px; margin-bottom: 12px;
    }
    .toolbar label { display:flex; flex-direction:column; gap:4px; font-size:12px; color: var(--muted); }
    .toolbar input { min-width: 220px; padding: 8px 10px; border: 1px solid var(--line); border-radius: 8px; }
    #status { min-height: 1.25em; font-size: 13px; margin: 0 0 10px; }
    #status.ok { color: var(--ok); }
    #status.err { color: var(--danger); }
    .hist-block { border: 1px solid var(--line); border-radius: 12px; padding: 8px 12px; margin-bottom: 8px; background:#fcfdfc; }
    .hist-block summary { cursor: pointer; padding: 6px 0; }
    .split { display:grid; grid-template-columns: 1.2fr .8fr; gap: 14px; }
    .empty { padding: 24px; text-align:center; color: var(--muted); }
    .footnote { color: var(--muted); font-size: 12px; margin-top: 8px; }
    tr.dev-row[data-unknown="1"] { background: #fffaf0; }
    @media (max-width: 960px) {
      .kpis { grid-template-columns: repeat(2, minmax(0, 1fr)); }
      .split { grid-template-columns: 1fr; }
    }
    @media (max-width: 560px) {
      .kpis { grid-template-columns: 1fr; }
      .id-full { display:none; }
    }
  </style>
</head>
<body data-admin-required="${adminRequired}">
  <div class="wrap">
    <header class="app">
      <div class="brand">
        <h1>Scream 라이선스 현황</h1>
        <p>발급 디바이스·회사·이력을 한곳에서 확인하고 회사명/메모를 정리합니다.</p>
      </div>
      <div class="badge">저장소 <b>${escHtml(storageMode)}</b> · 기준 ${escHtml(formatKst(nowIso))}</div>
    </header>

    <section class="kpis">
      <div class="kpi"><div class="label">등록 디바이스</div><div class="value">${devices.length}</div><div class="sub">고유 device_id</div></div>
      <div class="kpi"><div class="label">회사 수</div><div class="value">${companies.length}</div><div class="sub">중복 회사명 기준</div></div>
      <div class="kpi"><div class="label">총 발급 횟수</div><div class="value">${issues.length}</div><div class="sub">최근 7일 ${recent7d}회</div></div>
      <div class="kpi warn"><div class="label">회사명 미지정</div><div class="value">${unknownCount}</div><div class="sub">Unknown — 정리 필요</div></div>
      <div class="kpi"><div class="label">재발급 디바이스</div><div class="value">${reissueCount}</div><div class="sub">발급 2회 이상 · 최근 ${escHtml(formatKst(lastIssueAt))}</div></div>
    </section>

    <nav class="nav" id="mainNav">
      <button type="button" class="active" data-tab="overview">한눈 보기</button>
      <button type="button" data-tab="companies">회사 관리</button>
      <button type="button" data-tab="devices">디바이스 관리</button>
      <button type="button" data-tab="history">발급 이력</button>
    </nav>

    <div class="toolbar ${adminRequired === '1' ? '' : 'hidden'}" id="adminBar">
      <label>관리 토큰
        <input id="adminToken" type="password" autocomplete="off" placeholder="LICENSE_ADMIN_TOKEN" />
      </label>
      <p class="muted" style="margin:0;flex:1;min-width:200px;">편집/삭제 시 필요합니다. 이 브라우저 sessionStorage에만 저장됩니다.</p>
    </div>
    <div id="status"></div>

    <section id="tab-overview" class="tab">
      <div class="split">
        <div class="panel">
          <div class="panel-head">
            <h2>회사별 요약</h2>
            <span class="muted">카드 클릭 → 디바이스 필터 · 「회사 관리」에서 수정</span>
          </div>
          <div class="co-grid">${companyCards || '<div class="empty">등록된 회사가 없습니다.</div>'}</div>
        </div>
        <div class="panel">
          <div class="panel-head"><h2>최근 발급</h2><span class="muted">최신 8건 · 전체 수정은「발급 이력」</span></div>
          <div class="table-scroll" style="max-height:420px">
            <table>
              <thead><tr><th>시각</th><th>회사</th><th>Device</th></tr></thead>
              <tbody>${recentRows || '<tr><td colspan="3" class="empty">발급 이력 없음</td></tr>'}</tbody>
            </table>
          </div>
          <p class="footnote">시각은 Asia/Seoul(KST). 회사명 오타·미지정은 「회사 관리」에서 일괄 수정하세요.</p>
        </div>
      </div>
    </section>

    <section id="tab-companies" class="tab hidden">
      <div class="panel">
        <div class="panel-head">
          <h2>회사 관리</h2>
          <span class="muted">회사명 변경 시 소속 디바이스·발급 이력에 모두 반영</span>
        </div>
        <div class="table-scroll">
          <table>
            <thead>
              <tr>
                <th>회사명</th>
                <th>메모</th>
                <th>담당/연락처</th>
                <th>디바이스</th>
                <th>발급</th>
                <th>최근</th>
                <th>동작</th>
              </tr>
            </thead>
            <tbody id="companyTable">
              ${companyRows || '<tr><td colspan="7" class="empty">회사 없음</td></tr>'}
            </tbody>
          </table>
        </div>
        <p class="footnote">저장 = 회사명/메모/연락처 갱신(이름 변경 시 일괄 교체). 삭제 = 해당 회사 디바이스·발급 이력까지 제거(확인).</p>
      </div>
    </section>

    <section id="tab-devices" class="tab hidden">
      <div class="panel">
        <div class="panel-head">
          <h2>디바이스 관리</h2>
          <span class="muted" id="filterCount">${devices.length}대 표시</span>
        </div>
        <div class="filters">
          <input type="search" id="q" placeholder="회사·Device ID·메모 검색" />
          <select id="companyFilter">
            <option value="">전체 회사</option>
            ${companies
              .map((c) => `<option value="${escHtml(c.company)}">${escHtml(c.company)} (${c.devices})</option>`)
              .join('')}
          </select>
          <label class="muted" style="display:flex;align-items:center;gap:6px;">
            <input type="checkbox" id="onlyUnknown" /> Unknown만
          </label>
        </div>
        <div class="chips" id="companyChips">
          <button type="button" class="chip active" data-filter-company="">전체 <span>${devices.length}</span></button>
          ${companyChips}
        </div>
        <div class="table-scroll">
          <table>
            <thead>
              <tr>
                <th>Device ID</th>
                <th>회사</th>
                <th>메모</th>
                <th>발급횟수</th>
                <th>최초 (KST)</th>
                <th>최근 (KST)</th>
                <th>동작</th>
              </tr>
            </thead>
            <tbody id="deviceTable">
              ${deviceRows || '<tr><td colspan="7" class="empty">디바이스 없음</td></tr>'}
            </tbody>
          </table>
        </div>
        <p class="footnote">모든 칸 수정 후 저장. 시각 형식: YYYY-MM-DD HH:mm (한국시간). 삭제는 확인 시 발급 이력까지 지울 수 있습니다.</p>
      </div>
    </section>

    <section id="tab-history" class="tab hidden">
      <div class="panel">
        <div class="panel-head">
          <h2>발급 이력 (수정 가능)</h2>
          <div style="display:flex;gap:6px;">
            <button type="button" id="expandAll">모두 펼치기</button>
            <button type="button" id="collapseAll">모두 접기</button>
          </div>
        </div>
        ${historySections || '<div class="empty">발급 이력이 없습니다.</div>'}
        <p class="footnote">각 행의 시각·회사·Device ID를 고친 뒤 저장하세요.</p>
      </div>
    </section>
  </div>

  <script>
    (function () {
      var adminRequired = document.body.dataset.adminRequired === '1';
      var tokenInput = document.getElementById('adminToken');
      var statusEl = document.getElementById('status');
      var KEY = 'scream_license_admin_token';
      var q = document.getElementById('q');
      var companyFilter = document.getElementById('companyFilter');
      var onlyUnknown = document.getElementById('onlyUnknown');
      var filterCount = document.getElementById('filterCount');

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
        var h = { 'Content-Type': 'application/json', Accept: 'application/json' };
        if (adminRequired && tokenInput && tokenInput.value) h['X-Admin-Token'] = tokenInput.value;
        return h;
      }

      function showTab(name) {
        ['overview', 'companies', 'devices', 'history'].forEach(function (t) {
          var el = document.getElementById('tab-' + t);
          if (el) el.classList.toggle('hidden', t !== name);
        });
        document.querySelectorAll('#mainNav button').forEach(function (b) {
          b.classList.toggle('active', b.getAttribute('data-tab') === name);
        });
      }

      document.getElementById('mainNav').addEventListener('click', function (ev) {
        var btn = ev.target.closest('button[data-tab]');
        if (!btn) return;
        showTab(btn.getAttribute('data-tab'));
      });

      function applyFilter(companyOpt) {
        if (typeof companyOpt === 'string') {
          companyFilter.value = companyOpt;
          onlyUnknown.checked = companyOpt === 'Unknown';
        }
        var term = (q.value || '').trim().toLowerCase();
        var company = companyFilter.value || '';
        var unk = onlyUnknown.checked;
        var rows = document.querySelectorAll('#deviceTable tr.dev-row');
        var shown = 0;
        rows.forEach(function (tr) {
          var ok = true;
          if (company && tr.getAttribute('data-company') !== company) ok = false;
          if (unk && tr.getAttribute('data-unknown') !== '1') ok = false;
          if (term && (tr.getAttribute('data-search') || '').indexOf(term) === -1) ok = false;
          tr.classList.toggle('hidden', !ok);
          if (ok) shown += 1;
        });
        filterCount.textContent = shown + '대 표시';
        document.querySelectorAll('#companyChips .chip').forEach(function (chip) {
          var c = chip.getAttribute('data-filter-company') || '';
          chip.classList.toggle('active', c === company || (!company && c === ''));
        });
      }

      q.addEventListener('input', function () { applyFilter(); });
      companyFilter.addEventListener('change', function () { applyFilter(); });
      onlyUnknown.addEventListener('change', function () { applyFilter(); });

      document.getElementById('companyChips').addEventListener('click', function (ev) {
        var chip = ev.target.closest('.chip');
        if (!chip) return;
        showTab('devices');
        applyFilter(chip.getAttribute('data-filter-company') || '');
      });

      document.querySelectorAll('.co-card').forEach(function (card) {
        card.addEventListener('click', function () {
          showTab('devices');
          applyFilter(card.getAttribute('data-company') || '');
        });
      });

      document.getElementById('expandAll').addEventListener('click', function () {
        document.querySelectorAll('.hist-block').forEach(function (d) { d.open = true; });
      });
      document.getElementById('collapseAll').addEventListener('click', function () {
        document.querySelectorAll('.hist-block').forEach(function (d) { d.open = false; });
      });

      async function saveCompany(tr) {
        var from = tr.getAttribute('data-from');
        var to = tr.querySelector('.inp-co-name').value.trim() || 'Unknown';
        var note = tr.querySelector('.inp-co-note').value;
        var contact = tr.querySelector('.inp-co-contact').value;
        setStatus('회사 저장 중…');
        try {
          var res = await fetch('/api/companies', {
            method: 'PATCH',
            headers: headers(),
            body: JSON.stringify({ from: from, to: to, note: note, contact: contact }),
          });
          var data = await res.json().catch(function () { return {}; });
          if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
          setStatus('회사 저장 완료 (' + (data.deviceHits || 0) + '대, 이력 ' + (data.issueHits || 0) + '건)', true);
          setTimeout(function () { location.reload(); }, 450);
        } catch (e) {
          setStatus('회사 저장 실패: ' + e.message, false);
        }
      }

      async function deleteCompany(tr) {
        var name = tr.getAttribute('data-from');
        if (!confirm('회사 “‘ + name + '” 를 삭제할까요?\\n소속 디바이스와 발급 이력이 함께 삭제됩니다.')) return;
        setStatus('회사 삭제 중…');
        try {
          var res = await fetch('/api/companies', {
            method: 'DELETE',
            headers: headers(),
            body: JSON.stringify({ name: name, purgeDevices: true, purgeIssues: true }),
          });
          var data = await res.json().catch(function () { return {}; });
          if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
          setStatus('회사 삭제 완료', true);
          setTimeout(function () { location.reload(); }, 400);
        } catch (e) {
          setStatus('회사 삭제 실패: ' + e.message, false);
        }
      }

      document.getElementById('companyTable').addEventListener('click', function (ev) {
        var t = ev.target;
        var tr = t.closest('tr.co-row');
        if (!tr) return;
        if (t.classList.contains('btn-co-save')) saveCompany(tr);
        if (t.classList.contains('btn-co-del')) deleteCompany(tr);
      });

      async function saveRow(tr) {
        var id = tr.getAttribute('data-id');
        var company = tr.querySelector('.inp-company').value.trim();
        var note = tr.querySelector('.inp-note').value;
        var issueCount = tr.querySelector('.inp-count').value;
        var firstSeenAt = tr.querySelector('.inp-first').value;
        var lastSeenAt = tr.querySelector('.inp-last').value;
        setStatus('저장 중…');
        try {
          var res = await fetch('/api/devices/' + encodeURIComponent(id), {
            method: 'PATCH',
            headers: headers(),
            body: JSON.stringify({
              company: company || 'Unknown',
              note: note,
              issueCount: issueCount,
              firstSeenAt: firstSeenAt,
              lastSeenAt: lastSeenAt,
            }),
          });
          var data = await res.json().catch(function () { return {}; });
          if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
          setStatus('디바이스 저장 완료', true);
          setTimeout(function () { location.reload(); }, 450);
        } catch (e) {
          setStatus('저장 실패: ' + e.message, false);
        }
      }

      async function deleteRow(tr) {
        var id = tr.getAttribute('data-id');
        if (!confirm('이 디바이스 기록을 삭제할까요?\\n' + id)) return;
        var purge = confirm('발급 이력까지 함께 삭제할까요?\\n(취소하면 디바이스 목록만 제거)');
        setStatus('삭제 중…');
        try {
          var url = '/api/devices/' + encodeURIComponent(id) + (purge ? '?purgeIssues=1' : '');
          var res = await fetch(url, { method: 'DELETE', headers: headers() });
          var data = await res.json().catch(function () { return {}; });
          if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
          setStatus('삭제 완료', true);
          setTimeout(function () { location.reload(); }, 400);
        } catch (e) {
          setStatus('삭제 실패: ' + e.message, false);
        }
      }

      document.getElementById('deviceTable').addEventListener('click', function (ev) {
        var t = ev.target;
        if (t.classList.contains('btn-copy')) {
          var v = t.getAttribute('data-copy') || '';
          if (navigator.clipboard && navigator.clipboard.writeText) {
            navigator.clipboard.writeText(v).then(function () { setStatus('Device ID 복사됨', true); });
          } else {
            setStatus(v, true);
          }
          return;
        }
        var tr = t.closest('tr[data-id]');
        if (!tr) return;
        if (t.classList.contains('btn-save')) saveRow(tr);
        if (t.classList.contains('btn-del')) deleteRow(tr);
      });

      async function saveIssue(tr) {
        var matchDevice = tr.getAttribute('data-device');
        var matchIssued = tr.getAttribute('data-issued');
        var issuedAt = tr.querySelector('.inp-iss-at').value;
        var company = tr.querySelector('.inp-iss-company').value.trim();
        var deviceId = tr.querySelector('.inp-iss-device').value.trim();
        setStatus('이력 저장 중…');
        try {
          var res = await fetch('/api/issues', {
            method: 'PATCH',
            headers: headers(),
            body: JSON.stringify({
              match: { deviceId: matchDevice, issuedAt: matchIssued },
              issuedAt: issuedAt,
              company: company || 'Unknown',
              deviceId: deviceId,
            }),
          });
          var data = await res.json().catch(function () { return {}; });
          if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
          setStatus('이력 저장 완료', true);
          setTimeout(function () { location.reload(); }, 450);
        } catch (e) {
          setStatus('이력 저장 실패: ' + e.message, false);
        }
      }

      async function deleteIssue(tr) {
        var matchDevice = tr.getAttribute('data-device');
        var matchIssued = tr.getAttribute('data-issued');
        if (!confirm('이 발급 이력을 삭제할까요?')) return;
        setStatus('이력 삭제 중…');
        try {
          var res = await fetch('/api/issues', {
            method: 'DELETE',
            headers: headers(),
            body: JSON.stringify({ match: { deviceId: matchDevice, issuedAt: matchIssued } }),
          });
          var data = await res.json().catch(function () { return {}; });
          if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
          setStatus('이력 삭제 완료', true);
          setTimeout(function () { location.reload(); }, 400);
        } catch (e) {
          setStatus('이력 삭제 실패: ' + e.message, false);
        }
      }

      document.querySelectorAll('.issueTable').forEach(function (tbody) {
        tbody.addEventListener('click', function (ev) {
          var t = ev.target;
          var tr = t.closest('tr.iss-row');
          if (!tr) return;
          if (t.classList.contains('btn-iss-save')) saveIssue(tr);
          if (t.classList.contains('btn-iss-del')) deleteIssue(tr);
        });
      });

      applyFilter();
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

