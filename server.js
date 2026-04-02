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

const DATA_DIR = path.join(__dirname, 'data');
const LICENSE_DB_PATH = path.join(DATA_DIR, 'licenses.json');

// C 코드의 ENCRYPTION_KEY 와 동일한 비밀키 (MAC 용)
// 0x4B,0x59,0x42,0x45,0x52,0x5F,0x53,0x43,0x52,0x45,0x41,0x4D,0x5F,0x4D,0x4F,0x44,
// 0x45,0x4C,0x5F,0x32,0x30,0x32,0x35,0x5F,0x56,0x31,0x5F,0x53,0x45,0x43,0x52,0x45
const MAC_KEY = Buffer.from(
  '4b594245525f53435245414d5f4d4f44454c5f323032355f56315f5345435245',
  'hex'
);

function loadLicenseDb() {
  try {
    const buf = fs.readFileSync(LICENSE_DB_PATH, 'utf8');
    return JSON.parse(buf);
  } catch (e) {
    return { devices: {} };
  }
}

function saveLicenseDb(db) {
  if (!fs.existsSync(DATA_DIR)) {
    fs.mkdirSync(DATA_DIR, { recursive: true });
  }
  fs.writeFileSync(LICENSE_DB_PATH, JSON.stringify(db, null, 2), 'utf8');
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
    rec.issueCount += 1;
    rec.lastSignature = signatureBuf.toString('hex');
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

/** Render 등: HTTP 한 포트만 사용 (POST /issue → 88바이트 octet-stream) */
function handleRenderHttp(req, res) {
  const url = (req.url || '').split('?')[0];

  if (req.method === 'GET' && (url === '/' || url === '/index.html')) {
    const html = renderHtmlDashboard();
    res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
    res.end(html);
    return;
  }

  if (req.method === 'GET' && url === '/health') {
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('ok');
    return;
  }

  if (req.method === 'POST' && (url === '/issue' || url === '/license')) {
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

// Render: RENDER=true 이면 TCP 대신 HTTP만 process.env.PORT 에 바인딩
const isRender = process.env.RENDER === 'true';

if (isRender) {
  const port = Number(process.env.PORT) || 10000;
  const renderHttp = http.createServer(handleRenderHttp);
  renderHttp.listen(port, '0.0.0.0', () => {
    console.log(`Render mode: HTTP 0.0.0.0:${port}  GET /  GET /health  POST /issue`);
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
}

// 간단한 HTML 대시보드 서버
function renderHtmlDashboard() {
  const db = loadLicenseDb();
  const devices = Object.values(db.devices || {});
  const issues = db.issues || [];

  // 회사별 집계
  const companyStats = {};
  for (const d of devices) {
    const company = d.company || 'Unknown';
    if (!companyStats[company]) {
      companyStats[company] = 0;
    }
    companyStats[company] += 1;
  }

  const companyRows = Object.entries(companyStats)
    .sort((a, b) => b[1] - a[1])
    .map(
      ([company, count]) =>
        `<tr><td>${company}</td><td style="text-align:right">${count}</td></tr>`
    )
    .join('\n');

  const deviceRows = devices
    .sort((a, b) => (a.firstSeenAt || '').localeCompare(b.firstSeenAt || ''))
    .map(
      (d) => `
        <tr>
          <td><code>${d.deviceId}</code></td>
          <td>${d.company || 'Unknown'}</td>
          <td style="text-align:right">${d.issueCount || 0}</td>
          <td>${d.firstSeenAt || ''}</td>
          <td>${d.lastSeenAt || ''}</td>
        </tr>
      `
    )
    .join('\n');

  // 회사별 발급 이력 그룹핑
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
              <td>${iss.issuedAt || ''}</td>
              <td><code>${iss.deviceId}</code></td>
            </tr>
          `
        )
        .join('\n');

      return `
        <h3 id="company-${company}">${company}</h3>
        <table>
          <thead>
            <tr>
              <th>발급 시간</th>
              <th>Device ID</th>
            </tr>
          </thead>
          <tbody>
            ${rows || '<tr><td colspan="2">발급 이력 없음</td></tr>'}
          </tbody>
        </table>
      `;
    })
    .join('\n');

  return `<!DOCTYPE html>
<html lang="ko">
<head>
  <meta charset="UTF-8" />
  <title>Scream License Dashboard</title>
  <style>
    body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; margin: 24px; background: #f5f7fb; color: #222; }
    h1 { margin-bottom: 8px; }
    table { border-collapse: collapse; width: 100%; margin-bottom: 24px; background: #fff; }
    th, td { border: 1px solid #ddd; padding: 6px 8px; font-size: 13px; }
    th { background: #f0f2f7; text-align: left; }
    code { font-family: "SF Mono", Menlo, Consolas, monospace; font-size: 12px; }
    .section-title { margin-top: 24px; margin-bottom: 8px; }
  </style>
</head>
<body>
  <h1>Scream License Dashboard</h1>
  <p>총 디바이스 수: ${devices.length}</p>
  <p>총 발급 이력 수: ${issues.length}</p>

  <h2 class="section-title">회사별 디바이스 수</h2>
  <table>
    <thead>
      <tr><th>회사</th><th>디바이스 수</th></tr>
    </thead>
    <tbody>
      ${companyRows || '<tr><td colspan="2">데이터 없음</td></tr>'}
    </tbody>
  </table>

  <h2 class="section-title">디바이스별 라이센스 정보</h2>
  <table>
    <thead>
      <tr>
        <th>Device ID</th>
        <th>회사</th>
        <th>발급 횟수</th>
        <th>최초 발급 시간</th>
        <th>마지막 발급 시간</th>
      </tr>
    </thead>
    <tbody>
      ${deviceRows || '<tr><td colspan="5">데이터 없음</td></tr>'}
    </tbody>
  </table>

  <h2 class="section-title">회사별 발급 이력</h2>
  ${companyIssueSections || '<p>발급 이력이 없습니다.</p>'}

  <p style="font-size:12px;color:#666;">
    회사명은 licenses.json 의 각 device 레코드의 <code>company</code> 필드를 수정해서 설정할 수 있습니다.
  </p>
</body>
</html>`;
}

if (!isRender) {
  const httpServer = http.createServer((req, res) => {
    if (req.url === '/' || req.url === '/index.html') {
      const html = renderHtmlDashboard();
      res.writeHead(200, { 'Content-Type': 'text/html; charset=utf-8' });
      res.end(html);
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not Found');
    }
  });

  httpServer.listen(HTTP_PORT, HTTP_HOST, () => {
    console.log(`License HTTP dashboard listening on http://${HTTP_HOST}:${HTTP_PORT}/`);
  });
}

