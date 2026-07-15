# Scream License Server

Rockchip 단말 OTP `device_id` 기반으로 **88바이트 바이너리 라이선스**를 발급하는 Node.js 서버입니다.  
MAC은 `SHAKE256(ENCRYPTION_KEY ‖ device_id)` 앞 64바이트이며, 펌웨어(`tflite_scream_wav3_lic.c` 등)와 동일한 규칙을 따릅니다.

**저장소:** [gourry7/scream_license_server](https://github.com/gourry7/scream_license_server) (이름에 공백 대신 밑줄)

---

## 목차

- [요구 사항](#요구-사항)
- [로컬 설치·실행](#로컬-설치실행)
- [프로토콜 요약](#프로토콜-요약)
- [Render 배포](#render-배포)
- [발급 이력 저장 (GitHub 권장)](#발급-이력-저장-github-권장)
- [GitHub 토큰 만들기](#github-토큰-만들기)
- [코드·Render 업데이트 방법](#코드render-업데이트-방법)
- [클라이언트 도구 (저장소 외부)](#클라이언트-도구-저장소-외부)
- [데이터·저장 위치](#데이터저장-위치)
- [보안 (MAC 키)](#보안-mac-키)
- [Git push (SSH/PAT)](#git-push-sshpat)

---

## 요구 사항

- **Node.js 18+** (`fetch` 사용)

```bash
cd license_server
npm install
cp data/licenses.json.example data/licenses.json   # 파일 모드 로컬 실행 시
```

---

## 로컬 설치·실행

```bash
npm start
```

| 모드 | 조건 | 동작 |
|------|------|------|
| **통합 HTTP** | `LICENSE_HTTP_UNIFIED=1` 또는 Render 환경(`RENDER` 등) | **한 포트**만 사용 |
| **레거시** | 위가 아닐 때 | TCP **2000** + 대시보드 HTTP **3000** |

### 레거시(로컬/VPS)

- **TCP 2000:** 한 줄 JSON `{"deviceId":"<32자 hex>","company":"..."}\n` → 응답 88바이트
- **HTTP 3000:** 대시보드 `http://127.0.0.1:3000/`

### 통합 HTTP (Render / `LICENSE_HTTP_UNIFIED=1`)

- `GET /` — 담당자용 HTML 대시보드 (표시된 항목 모두 웹에서 수정 가능)  
  - **한눈 보기:** KPI · 회사 카드 · 최근 발급  
  - **회사 관리:** 회사명 일괄 변경 · 메모/연락처 · 회사 단위 삭제  
  - **디바이스 관리:** 회사/메모/발급횟수/최초·최근 시각 편집 · 삭제  
  - **발급 이력:** 시각·회사·Device ID 편집 · 삭제 (KST)  
- `GET /health` — 헬스 체크 (Render용)  
- `GET /api/devices` — 디바이스 목록 JSON  
- `PATCH /api/devices/:deviceId` — 디바이스 필드 수정  
- `DELETE /api/devices/:deviceId` — 디바이스 삭제 (`?purgeIssues=1` 이면 이력도 삭제)  
- `PATCH /api/companies` — `{from,to,note,contact}` 회사명 일괄 변경  
- `DELETE /api/companies` — `{name}` 회사 소속 디바이스·이력 삭제  
- `PATCH /api/issues` / `DELETE /api/issues` — 발급 이력 1건 수정/삭제  
- `POST /issue` — 본문 JSON `{"deviceId":"<hex>","company":"..."}` → **88바이트** `application/octet-stream`

웹 편집을 잠그려면 Render Environment 에 `LICENSE_ADMIN_TOKEN` 을 넣고, 대시보드 상단에 같은 토큰을 입력합니다. (요청 헤더 `X-Admin-Token`)

---

## 프로토콜 요약

- 라이선스 파일: **88바이트** (magic `SCRM`, v1, 16바이트 device_id, 64바이트 MAC)  
- 발급·검증 로직은 서버와 디바이스 펌웨어가 동일 키·알고리즘을 공유해야 합니다.

---

## Render 배포

1. [Render Dashboard](https://dashboard.render.com) → **New** → **Web Service** → GitHub `gourry7/scream_license_server` 연결  
2. **Runtime:** Node  
3. **Build:** `npm install`  
4. **Start:** `node server.js`  
5. **Health Check Path:** `/health`  
6. Blueprint 사용 시 저장소 루트의 `render.yaml` 참고  

**무료 플랜 참고:** 일정 시간 요청이 없으면 **슬립** → 첫 요청이 지연될 수 있음. 로컬 디스크는 **휘발성**이므로 발급 이력은 **GitHub 연동**을 권장합니다.

### `render.yaml` 에 포함된 비밀 아님 env

- `LICENSE_HTTP_UNIFIED=1`  
- `LICENSE_GITHUB_REPO=gourry7/scream_license_server`  

**토큰은 저장소에 넣지 말고** Render 대시보드에서만 설정합니다.

---

## 발급 이력 저장 (GitHub 권장)

Render 인스턴스 디스크만 쓰면 재시작·재배포 시 이력이 사라질 수 있어, 서버는 **GitHub Contents API**로 이 저장소의 JSON을 읽고 커밋할 수 있습니다.

| 항목 | 값 |
|------|-----|
| **저장소 (기본)** | `gourry7/scream_license_server` |
| **파일** | `data/licenses.json` |
| **브랜치 (기본)** | `main` |

웹에서 보는 예:  
`https://github.com/gourry7/scream_license_server/blob/main/data/licenses.json`

### 저장 백엔드 우선순위

1. **`LICENSE_GITHUB_TOKEN` 이 설정된 경우** → GitHub  
2. **`DATABASE_URL` 이 있는 경우** → PostgreSQL (`pg`)  
3. 그 외 → 로컬 파일 `data/licenses.json`

### 선택 환경 변수

| 변수 | 설명 |
|------|------|
| `LICENSE_GITHUB_REPO` | 생략 시 `gourry7/scream_license_server` |
| `DEFAULT_LICENSE_GITHUB_REPO` | 기본 저장소 이름만 바꿀 때 |
| `LICENSE_GITHUB_PATH` | 기본 `data/licenses.json` |
| `LICENSE_GITHUB_BRANCH` | 기본 `main` |
| `LICENSE_DATA_DIR` | 파일 모드 시 디렉터리 (유료 디스크 마운트 경로 등) |
| `DATABASE_SSL` | `0` 이면 PostgreSQL SSL 끔 (로컬 DB 등) |
| `LICENSE_ADMIN_TOKEN` | 설정 시 대시보드 편집(PATCH/DELETE)에 `X-Admin-Token` 필요 |

---

## GitHub 토큰 만들기

1. GitHub → **Settings** → **Developer settings** → **Personal access tokens** → **Fine-grained tokens**  
2. **Generate new token**  
3. **Repository access:** `Only select repositories` → **`gourry7/scream_license_server`** 선택  
4. **Permissions → Repository permissions → Contents:** **Read and write**  
5. 생성 후 표시되는 토큰을 복사 (다시는 전체가 안 보임)

### Render에 넣기

1. Render → 해당 **Web Service** → **Environment**  
2. **Add Environment Variable**  
   - **Key:** `LICENSE_GITHUB_TOKEN`  
   - **Value:** 토큰 붙여넣기  
   - 가능하면 **Secret** 으로 저장  
3. **Save** → 자동 재배포되거나, **Manual Deploy → Deploy latest commit**  

`LICENSE_GITHUB_TOKEN` 만 넣으면 저장소는 기본값(`gourry7/scream_license_server`)으로 동작합니다.

---

## 코드·Render 업데이트 방법

```bash
cd license_server
git status
git add README.md server.js render.yaml package.json
git commit -m "설명"
git push origin main
```

GitHub에 `main` 으로 push 하면 Render가 **연동 저장소**를 쓰는 경우 **자동 빌드·배포**됩니다.  
자동이 아니면 Render에서 **Manual Deploy** 로 최신 커밋 배포.

---

## 클라이언트 도구 (저장소 외부)

이 저장소 밖 **screamData** 프로젝트에 있는 도구들과 연동할 수 있습니다.

| 도구 | 역할 |
|------|------|
| `request_license.py` | `LICENSE_HTTP_URL` 등으로 HTTPS `POST /issue`, 라이선스 파일 저장 |
| `watchdog_test_linux.py` | 기본 HTTPS URL로 라이선스 요청·ADB 푸시 등 GUI |

환경 변수 예:

```bash
export LICENSE_USE_HTTP=1
export LICENSE_HTTP_URL="https://scream-license-server.onrender.com/issue"
python3 request_license.py
```

(실제 서비스 URL은 Render 대시보드의 도메인에 맞춤.)

---

## 데이터·저장 위치

- **GitHub 모드:** 원격 저장소의 `data/licenses.json` 이 진본입니다.  
- **파일 모드:** 로컬 `data/licenses.json` — `.gitignore` 에 있어 **이 코드 저장소에는 보통 커밋하지 않습니다**. 로컬에서는 `licenses.json.example` 을 복사해 사용합니다.  
- 원격에 파일이 없으면 **첫 발급 시** API로 생성·커밋할 수 있습니다.

---

## 보안 (MAC 키)

`server.js` 의 `MAC_KEY` 는 펌웨어와 동일한 **대칭키**로, 공개 저장소에 있으면 **누구나 같은 코드로 라이선스를 생성할 수 있는 구조**에 가깝습니다.  
이 모델은 “서버가 신뢰된 발급자”이고, 키가 유출되면 위조가 가능합니다.

- 공개 배포 시: 키를 **비공개**(서버 전용 env, 비공개 저장소, 서명용 HSM 등)로 두는 방안을 검토하세요.  
- 이 README는 **키를 바꾸는 방법**만 안내하며, 운영 정책은 제품 요구에 맞게 결정하면 됩니다.

---

## Git push (SSH/PAT)

GitHub는 HTTPS `git push`에 **계정 비밀번호**를 받지 않습니다.

### SSH (권장)

1. `ssh-keygen -t ed25519 -C "your@email"`  
2. 공개키를 GitHub → **Settings → SSH and GPG keys** 에 등록  
3. `git remote add origin git@github.com:gourry7/scream_license_server.git`

### HTTPS + Personal Access Token

토큰을 비밀번호 대신 입력합니다.

### 초기 푸시 예시

```bash
cd license_server
git init
git add .
git commit -m "Initial import: scream license server"
git branch -M main
git remote add origin git@github.com:gourry7/scream_license_server.git
git push -u origin main
```

HTTPS URL: `https://github.com/gourry7/scream_license_server.git`
