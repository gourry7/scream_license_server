# Scream License Server

Rockchip 단말 OTP `device_id` 기반으로 88바이트 라이선스를 TCP로 발급하는 서버입니다.

**GitHub 저장소 이름:** `scream_license_server` (공백은 URL에 사용할 수 없어 밑줄 사용)

## 요구 사항

- Node.js 18+ 권장

## 설치

```bash
cd license_server
npm install
cp data/licenses.json.example data/licenses.json
```

## 실행

```bash
npm start
```

로컬(또는 일반 VPS)에서는:

- TCP **2000**: 라이선스 발급 (`{"deviceId":"<hex>","company":"..."}\n` → 88바이트)
- HTTP **3000**: 발급 이력 대시보드 `http://localhost:3000/`

### Render.com 에 올리기

Render는 **공개 포트가 HTTP(S) 하나**라서, 배포 시에는 **TCP 2000을 쓰지 않고** `RENDER=true` 일 때만 **HTTP 한 포트**로 동작합니다.

- `GET /` — 대시보드 (기존과 동일)
- `GET /health` — 헬스 체크 (Render용)
- `POST /issue` — 본문 JSON `{"deviceId":"<hex>","company":"..."}` → 응답 **88바이트** `application/octet-stream`

**Render 대시보드에서 Web Service 생성:**

1. New → Web Service → GitHub의 `scream_license_server` 연결  
2. Runtime: **Node**  
3. Build: `npm install`  
4. Start: `node server.js`  
5. (선택) Health Check Path: `/health`  

배포 후 URL이 예: `https://scream-license-server.onrender.com` 이면, 클라이언트(PC)에서는:

```bash
export LICENSE_USE_HTTP=1
export LICENSE_HTTP_URL="https://scream-license-server.onrender.com/issue"
python3 request_license.py
```

**주의 (무료 플랜):**

- 인스턴스가 **일정 시간 요청 없으면 슬립** → 첫 요청이 느릴 수 있음  
- **로컬 디스크는 재시작·재배포 시 초기화**될 수 있음 → 발급 이력을 유지하려면 아래 **GitHub 저장소 연동** 또는 `DATABASE_URL`(PostgreSQL) 사용

저장소 루트의 `render.yaml`로 Blueprint 배포도 가능합니다.

### 발급 이력을 GitHub에 저장·불러오기 (Render 권장)

Render는 디스크가 휘발성이므로, 발급 이력은 **[gourry7/scream_license_server](https://github.com/gourry7/scream_license_server)** 저장소의 `data/licenses.json` 에 **GitHub Contents API**로 읽고 커밋합니다.

1. GitHub에서 **Fine-grained personal access token** (또는 classic PAT `repo`) 발급: 저장소 `gourry7/scream_license_server` 에 대해 **Contents: Read and write** (또는 전체 `repo`).  
2. (선택) 저장소에 `data/licenses.json` 을 커밋해 두거나, 없으면 서버가 첫 발급 시 파일을 생성합니다. (로컬 개발용으로는 `.gitignore` 때문에 커밋되지 않을 수 있어도, API로 원격에 생성 가능합니다.)  
3. Render → Web Service → **Environment** → **Secret** 에 **`LICENSE_GITHUB_TOKEN`** 만 넣으면 됩니다.  
   - `LICENSE_GITHUB_REPO` 는 생략 시 자동으로 `gourry7/scream_license_server` 입니다 (`render.yaml`에도 동일).  
   - 다른 포크/저장소를 쓰려면 `LICENSE_GITHUB_REPO` 를 직접 지정하거나 `DEFAULT_LICENSE_GITHUB_REPO` 를 설정합니다.  
4. 선택 env: `LICENSE_GITHUB_PATH`(기본 `data/licenses.json`), `LICENSE_GITHUB_BRANCH`(기본 `main`).

**저장 백엔드 우선순위:** `LICENSE_GITHUB_TOKEN` 이 있으면 GitHub → 그다음 `DATABASE_URL`(PostgreSQL) → 없으면 로컬 `data/licenses.json` 파일.

## GitHub에 올리기 (비밀번호로 push 불가)

GitHub는 HTTPS `git push`에 **계정 비밀번호**를 받지 않습니다. 아래 중 하나를 쓰세요.

### 방법 A: SSH (권장)

1. PC에서 SSH 키 생성: `ssh-keygen -t ed25519 -C "your@email"`  
2. 공개키(`~/.ssh/id_ed25519.pub`) 내용을 GitHub → **Settings → SSH and GPG keys**에 등록  
3. 저장소 만들 때 SSH URL 사용: `git@github.com:USERNAME/REPO.git`

### 방법 B: HTTPS + Personal Access Token

1. GitHub → **Settings → Developer settings → Personal access tokens** 에서 토큰 생성 (repo 권한)  
2. `git push` 시 비밀번호 대신 **토큰** 입력  

### 초기 커밋 예시

```bash
cd license_server
git init
git add .
git commit -m "Initial import: scream license server"
git branch -M main
git remote add origin git@github.com:gourry7/scream_license_server.git
git push -u origin main
```

또는 HTTPS:

`git remote add origin https://github.com/gourry7/scream_license_server.git`

## 데이터

- **GitHub 모드(Render, 토큰 설정 시):** [scream_license_server](https://github.com/gourry7/scream_license_server) 의 `data/licenses.json` 이 진본입니다.  
- **파일 모드(토큰 없음·로컬):** `data/licenses.json` 은 `.gitignore` 로 **커밋하지 않습니다**. 로컬에서는 `licenses.json.example` 을 복사해 쓰세요.
