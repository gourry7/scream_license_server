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

- TCP **2000**: 라이선스 발급 (`{"deviceId":"<hex>","company":"..."}\n` → 88바이트)
- HTTP **3000**: 발급 이력 대시보드 `http://localhost:3000/`

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

`data/licenses.json`은 발급 이력을 담으므로 **저장소에 커밋하지 않습니다** (`.gitignore`). 서버마다 로컬에서 복사해 사용하세요.
