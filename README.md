# BYTE BACK | 점령된 자료실

### 웹 기반 접근 통제 및 비정상 접근 탐지 프로젝트

**프로젝트 개요**

BYTE BACK은 가상의 자료실을 대상으로 인증, 접근 통제, 비인가 접근 기록, 반복 접근 탐지, 관리자 보안 관제를 구현한 웹 보안 실습 프로젝트입니다.

초기에는 공개된 가상 자료를 확인하는 단계에서 출발하여, Supabase 인증과 데이터베이스 보안 정책을 적용하고 접근 시도를 기록·분석하는 구조로 발전시켰습니다.

**배포 주소:** https://choi-bujang-secret-vault-five-kappa.vercel.app/

## 1. 사용 기술

| 구분 | 기술 |
|---|---|
| 프론트엔드 | HTML, CSS, JavaScript |
| 서버 API | Vercel Serverless Functions |
| 데이터베이스 | Supabase PostgreSQL |
| 사용자 인증 | Supabase Auth |
| 접근 통제 | JWT 인증, Row Level Security(RLS) |
| 배포 및 형상 관리 | GitHub, Vercel |
| 보안 이벤트 관리 | Supabase 보안 로그 테이블 |

## 2. 주요 구현 기능

**사용자 인증 및 접근 통제**

- 이메일과 비밀번호를 이용한 사용자 로그인
- 인증되지 않은 API 요청에 HTTP 401 반환
- 사용자 UID와 자료 소유자 ID를 비교하여 본인 자료만 조회
- 관리자 UID 검증을 통한 관리자 API 접근 제한
- 일반 사용자의 관리자 API 접근 시 HTTP 403 반환

**비정상 접근 기록 및 탐지**

- 비로그인 상태의 자료 접근 시도를 서버 로그에 기록
- 접근 이벤트를 Supabase `security_events` 테이블에 저장
- 최근 5분 동안 비인가 접근이 5회 이상 발생하면 `ALERT` 판정
- 관리자 대시보드에서 접근 횟수와 위험 수준 조회

## 3. 시스템 구조

```text
사용자 브라우저
      |
      v
Vercel 웹사이트
      |
      +-- Supabase Auth (로그인)
      |
      +-- /api/note
      |      |
      |      +-- 사용자 인증 확인
      |      +-- 본인 소유 자료 조회
      |      +-- 비인가 접근 로그 저장
      |
      +-- /api/security-status
             |
             +-- 관리자 UID 확인
             +-- 보안 이벤트 조회
             +-- 위험 수준 판정
```

## 4. 보안 테스트 결과

| 테스트 | 기대 결과 | 실제 결과 |
|---|---|---|
| 비로그인 자료 접근 | HTTP 401 | 성공 |
| 관리자 계정 자료 조회 | 소유 자료 4개 조회 | 성공 |
| 일반 사용자 자료 조회 | 다른 사용자 자료 미노출 | 성공 |
| 비인가 접근 기록 | 데이터베이스에 이벤트 저장 | 성공 |
| 5분 내 5회 이상 비인가 접근 | ALERT 판정 | 성공 |
| 관리자 보안 대시보드 | 접근 횟수 및 위험 수준 표시 | 성공 |
| 일반 사용자 관리자 API 접근 | HTTP 403 | 성공 |

## 5. 문제 해결 경험

### 공개 정적 파일을 통한 접근 통제 우회 문제 해결

최종 보안 점검 과정에서 인증이 필요한 API와 별개로 `/data.json` 경로를 통해 실습용 가상 자료가 공개되는 문제를 발견했습니다.

원인을 추적한 결과, 초기 실습용 빌드 스크립트가 `data.json`을 공개 디렉터리인 `public`에 복사하고 있었습니다.

이에 `scripts/build-public.mjs`를 수정하여 공개 자료 생성 및 배포 과정을 제거했습니다.

수정 후 Vercel에 재배포하고 해당 경로에서 HTTP 404 응답이 반환되는 것을 확인했습니다. 또한 기존 관리자 로그인, 보호된 자료 4개 조회, 보안 관제 화면이 정상적으로 작동하는지도 재검증했습니다.

이 과정을 통해 API 인증뿐 아니라 정적 파일 배포 경로까지 함께 점검해야 한다는 점을 배웠습니다.

**Supabase 데이터베이스 권한 오류 해결**

API 연동 과정에서 데이터베이스 요청이 HTTP 403 오류를 반환하는 문제가 발생했습니다.

Supabase의 테이블 권한을 확인하는 SQL을 실행하여 필요한 `SELECT` 권한이 부여되지 않았음을 확인했습니다.

이후 역할별로 필요한 권한을 부여하여 문제를 해결했으며, RLS 정책과 테이블 권한이 별개로 적용된다는 점을 실습을 통해 이해했습니다.

**관리자 API 접근 제어 검증**

관리자 화면을 단순히 숨기는 방식만으로는 접근 통제가 충분하지 않다는 점을 고려하여 서버 API에서도 사용자 UID를 검증하도록 구현했습니다.

일반 사용자 계정으로 관리자 API를 직접 호출해 HTTP 403 응답을 확인했습니다.

## 6. 프로젝트 범위 및 한계

본 프로젝트는 가상 자료를 이용한 교육용 보안 실습입니다.

현재 반복 접근 탐지는 개별 IP나 사용자별 공격 패턴이 아닌 전체 비인가 접근 이벤트 횟수를 기준으로 판정합니다. 보안 현황은 관리자가 새로고침할 때 갱신되며, 실시간 자동 알림이나 자동 차단 기능은 구현하지 않았습니다.

따라서 실제 운영 환경의 침입 탐지 시스템이나 전문 보안 관제 솔루션과는 차이가 있습니다.

## 7. 향후 개선 방향

- IP 또는 사용자별 접근 시도 구분
- 탐지 기준 및 이벤트 유형 세분화
- 관리자 보안 이벤트 이력 조회
- 보안 로그 보존 및 접근 권한 관리 강화
- 자동 경고 알림 기능 추가

---

**본 프로젝트에 사용된 자료는 모두 실습용 가상 데이터입니다. 실제 개인정보 및 비밀키는 저장소에 포함하지 않습니다.**

# BYTE BACK 방어전 시작 틀 R5

이 저장소는 1단계에서 학생 본인이 GitHub 저장소와 Vercel 배포를 만드는 출발점입니다. 포함된 메모 네 건은 가상 자료입니다. 실제 학생 자료, 토큰, 비밀키를 넣지 마세요.

## 학생이 하는 일: 세 걸음

1. GitHub 계정을 만듭니다.
2. 방어전 1단계 카드의 **Deploy** 버튼을 누릅니다. Vercel에 GitHub로 로그인하고, 새 저장소가 **본인 계정의 Public 저장소**인지 확인한 뒤 Deploy를 누릅니다.
3. 배포가 끝나면 화면에 나온 `https://…vercel.app` 주소를 방어전 1단계 카드에 붙여넣고 제출합니다. 저장소 주소나 설정 파일은 적지 않습니다.

배포가 끝나면 `/`에서 점령된 가상 자료실을 볼 수 있습니다. `/data.json`에는 같은 가상 메모가 공개됩니다. 이 공개 상태를 확인하는 것이 1단계의 출발점입니다. 1단계 접수와 심판 판정은 포털에서 확인합니다.

## 시작 틀의 자동 처리

`vercel.json`은 정적 결과물 `public`을 배포합니다. 빌드 명령 `npm run build`는 Vercel이 제공하는 GitHub 저장소 소유자·이름, 커밋 SHA, 배포 URL을 검증하고 `public/aleph.json`을 생성합니다. 이 값이 없으면 빌드가 실패하므로, 성공한 것처럼 빈 주소를 내보내지 않습니다. `aleph.json`의 내용만으로 저장소 소유권이나 방어 성공을 인정하지 않습니다. 심판이 공개 저장소의 실제 커밋과 배포된 자료를 따로 대조해야 합니다.

`aleph.config.json`의 `repoUrl`과 `publicAppUrl`은 이전 제출 묶음 방식의 자리표시자입니다. 1단계에서는 학생이 편집하지 않습니다. 2단계 이후 코딩 도구가 필요한 설정과 보호 기능을 단계별로 작성합니다. `npm run bundle`과 `bundle-notes.json`도 1단계의 세 걸음에는 포함되지 않습니다.

로컬에서 가상 화면만 확인할 때는 `npm run build -- --local`을 사용합니다. 로컬 실행은 Vercel 배포나 심판 접수를 증명하지 않습니다. 저장소의 `src/attack-check.mjs`는 실제 배포가 된 뒤 `/data.json`을 비로그인으로 요청해 공개 가상 메모의 확인 표시를 읽습니다.

## 다음 단계의 코딩 도구에 전달할 규칙

[AGENTS.md](AGENTS.md)를 먼저 읽히고 한 번에 한 제작 단위만 요청하세요. 2단계부터는 자료 보호를 구현할 때 `public/data.json`을 복사하는 1단계 빌드 흐름도 함께 바꿔야 합니다. 3단계 이후의 로그인, 허용 경로, 5단계의 원본 API 주소, 6단계 이후 정책 규칙은 해당 단계 원고와 계약에 맞춰 추가합니다. 비밀번호·토큰·서버 전용 키·실제 학생 기록을 코드, Git, 제출 묶음에 넣지 않습니다.

`src/decider.mjs`와 `src/detect.mjs`의 로컬 시험은 반 엔진이나 운영 심판의 결과가 아닙니다. 1단계 이후 제출 묶음 계약 `aleph.defense.submission.v2`는 `scripts/bundle.mjs`에 남아 있으며, 코딩 도구가 해당 단계의 최신 배포 주소와 Git 원격을 맞춘 뒤 사용합니다.


## 7단계 저장점 — 복합 이상 접속 추가 확인

- 1~5단계의 Supabase 인증, 서버 로그인 API, 소유자별 메모 격리, 비인가 접근 차단과 보안 이벤트 기록을 보존합니다.
- 6단계 `device_registered` 규칙을 유지하며, 학생이 확인한 실제 6단계 심판 점수는 100점입니다.
- 7단계에서는 엔진 계약의 `signals`, `recentEvents`, `stepUp`만 사용합니다. `judge_fixture` 출처에서 비정상 시각, 낯선 네트워크, 최근 다량의 위험 사건이 겹칠 때 `step_up`을 반환합니다.
- 출처 불명·누락된 값을 임의의 정상 위치·시각·네트워크로 채우지 않습니다. 지역 하나만으로 영구 차단하지 않습니다.
- 계약상 `stepUp.verified`와 `authAgeSeconds`가 제공되지만, 실제 재로그인 확인·자료 차단은 운영 엔진에서 별도 실측해야 합니다. 로컬 가상 연습은 운영 심판 결과가 아닙니다.

Windows PowerShell 검증 명령: `npm.cmd install`, `npm.cmd run decider:test`, `npm.cmd run fixture:7`, `npm.cmd run bundle`. 번들 생성 전 커밋과 Git 상태를 확인합니다. `bundle-notes.json` 및 `artifacts/submission.json`은 커밋하지 않습니다.


## 8단계 저장점 — 자원 구역별 접근 정책

- 7단계 실제 채점 결과: 100점(학생 확인). 1~7단계 로그인·메모 소유권·기기 등록·추가 인증 규칙을 보존합니다.
- 판정기 `resource_zone`: `notes` 서비스의 단일 ID 메모 경로와 `notices` 서비스의 단일 ID 공지 GET만 허용합니다. 메모 전체 목록, 공지 쓰기, 강사 자료, 알 수 없는 서비스·경로는 거부합니다.
- 엔진 요청 계약의 `service`, `method`, `path`, `route`를 사용합니다. 브라우저 role, 쿼리 문자열, 클라이언트 제공 사용자 ID를 신뢰하지 않습니다.
- 기존 실제 API `/api/note`, `/api/note/:id`는 검증된 로그인 주체와 DB `owner_id`를 비교합니다. 기존 화면 및 주소를 보존하기 위해 실제 API 경로는 변경하지 않았습니다. 판정기 가상 경로와 실제 API 경로는 서로 다른 계약입니다.
- 별도 강사 공지 수정 API나 강사 권한 검증 계약은 확인되지 않았으므로 임의로 만들지 않았습니다. 실제 다른 구역 요청 및 본인 정상 요청은 운영 환경에서 별도 확인해야 합니다.

Windows PowerShell: `npm.cmd install`, `npm.cmd run decider:test`, `npm.cmd run fixture:7`, `npm.cmd run bundle`. 로컬 테스트는 심판 점수가 아닙니다.


## 9단계 저장점 — 조회 폭주 탐지와 회수 제안

- 8단계 실제 심판 결과: 100점(학생 확인). 1~8단계 인증·메모 소유권·기기 등록·추가 인증·구역 정책은 그대로 보존합니다.
- `src/detect.mjs`의 `detect(events)`는 엔진이 검증해 제공하는 `at`, `method`, `identity.sub`만 사용합니다.
- 같은 가명 사용자에 대해 어느 10분 구간에서든 GET 121건 이상이면 `{action:"propose_revocation",reasonCode:"burst_read",subject:sub}`를 반환합니다. 정상 사건은 `{action:"observe"}`만 반환합니다.
- 다른 사용자의 조회는 합산하지 않고, 10분 밖의 사건을 같은 묶음으로 취급하지 않습니다. 메모 내용·토큰·실명·기기 번호를 저장하거나 출력하지 않습니다.
- 실제 회수 API, 세션 무효화 및 운영 반 엔진 연결은 구현하지 않았습니다. 로컬 연습은 운영 심판 결과가 아닙니다.

Windows PowerShell: `npm.cmd install`, `npm.cmd run detect:test`, `npm.cmd run bundle`. 실행되지 않은 점검은 미실행으로 기록합니다.


## 10단계 저장점 — 검증된 메모 사본에서 한 건 복원

- 9단계 실제 점수는 이번 저장점 작성 시 미확인입니다. 1~9단계의 인증·접근 정책·탐지 규칙은 변경하지 않았습니다.
- Supabase `public.defense_note_backups`에 2026-10-15 현재 상태의 비공개 기준 사본 5건을 생성하고 SHA-256 내용 해시 5/5 일치를 확인했습니다. 이는 과거 침해 전 백업이 아니라 현재 시점의 스냅샷입니다.
- 복구 서비스: `POST /api/restore/note`. 인증된 사용자 자신의 백업 메모 ID만 요청하며 JSON `{"id":123}`을 받습니다. 검증된 JWT의 `userId`로 소유자를 결정합니다.
- DB `restore_defense_note` 함수는 서버 전용 권한으로만 실행하고, 백업 소유자·ID·내용 SHA-256을 재검증합니다. 지정된 한 건만 INSERT/UPDATE하고, 다른 메모 및 `security_events` 감사 이력은 수정하지 않습니다.
- **정책 사본 검증 및 복원 전 확인 순서:** (1) 침해 전에 검증해 보관한 안전 정책 사본의 커밋 SHA·버전·해시와 검증 기록을 확인합니다. (2) 해당 버전의 `src/decider.mjs` 및 `aleph.config.json`을 저장소에서 **다시 읽어** 사본의 내용 해시와 검증 기록을 대조합니다. (3) 사본이 없거나 버전·해시·검증 기록이 누락/불일치하면 **즉시 중단**하며 정책을 복원하지 않습니다. (4) 검증에 성공한 경우에만 현재 시험 정책과 사본의 차이(diff)를 표시하고 **복원 대상 버전 및 바뀔 규칙·설정 항목과 영향 범위**를 실행 전에 확인받습니다. (5) 승인된 변경 항목만 시험 정책에 복원하고 다른 서비스 규칙과 감사 이력은 보존합니다. 실제 운영 정책은 변경하지 않습니다. 정책 사본의 독립적인 사전 검증 및 정책 복원 시험은 **미실행**입니다.
- 시험 계정 B의 ID 및 인증 토큰은 공개 저장소에 저장하지 않습니다. 복원 API 실제 호출·삭제 후 복원·A/B 교차 접근 검증은 미실행입니다.

복구 후 회귀 점검 순서:
1. `npm.cmd install` 및 `npm.cmd run build`로 의존성·배포 빌드를 확인합니다.
2. 비로그인 `GET /api/note`가 401인지 확인합니다.
3. A 본인 메모 정상 조회/수정, B의 A 메모 조회·수정·삭제 404를 확인합니다.
4. 등록되지 않은 기기 거부, 복합 이상 접속 step-up, 메모·공지 구역 거부를 `npm.cmd run decider:test` 및 `npm.cmd run fixture:7`로 연습합니다.
5. `npm.cmd run detect:test`로 정상 120건 observe 및 121건 propose_revocation을 확인합니다.
6. 시험 계정 B의 한 건을 의도적으로 변조/삭제하기 전, 비공개 사본을 **다시 읽고** 해당 사본의 **ID·소유자·내용 SHA-256 해시**를 각각 검증합니다. 사본이 없거나 무결성 검증에 실패하면 복원을 중단합니다. 승인된 시험에서만 `POST /api/restore/note`로 지정한 한 건을 복원한 뒤, **복원된 메모의 ID와 사본 ID, 소유자와 사본 소유자, 복원 내용에서 재계산한 SHA-256 해시와 사본 내용 해시를 각각 대조**합니다. 세 항목 모두 일치해야 성공으로 기록하며, 다른 메모·감사 기록의 불변 여부도 확인합니다. 실제 복원 시험은 **미실행**입니다.
7. `npm.cmd run bundle` 실행 전 git 상태 및 마지막 커밋을 확인합니다. 미실행 점검을 통과로 표시하지 않습니다.


## 11단계 저장점 — 설치형 웹앱과 서버 기기 승인 대기

- 10단계 채점 피드백에 따른 README 수정 후 학생이 해결됐다고 확인했습니다. 1~10단계 정책 판정기, 탐지기, 복구 API와 데이터는 보존합니다.
- `public/manifest.webmanifest`를 추가해 기존 자료실을 설치형 웹앱으로 표시합니다. 설치 자체는 기기 등록·인증이 아닙니다. 네트워크가 끊기면 오프라인 안내를 표시하며 보호 메모를 오프라인에 캐시하지 않습니다.
- 기기 승인 서비스 `GET /api/device-approval`(상태 조회), `POST /api/device-approval`(승인 요청). 검증된 로그인 주체의 요청을 Supabase 비공개 `defense_device_requests` 테이블에 `pending`으로 기록합니다. 기기 임의 식별값은 HttpOnly·Secure·SameSite=Strict 쿠키로 전송하고 DB에는 SHA-256 해시만 저장합니다. 브라우저 localStorage/sessionStorage에 **기기 키를 저장하지 않습니다**.
- 승인 버튼은 요청만 접수하며 `approved` 상태를 부여하지 않습니다. 서버에서 `approved`로 바뀌고 상태 조회가 확인된 경우에만 웹 화면에서 기존 자료실을 엽니다. 관리자 승인 작업은 별도 권한으로 수행해야 하며 현재 승인 관리 UI는 없습니다.
- **제약:** 기존 메모 API는 기존 JWT 소유권 검사 그대로이며 기기 승인 또는 요청 서명을 서버 API에서 강제하지 않습니다. 쿠키 기반 식별은 암호학적 요청 서명이 아니므로 경로·본문 변조 방어를 검증했다고 볼 수 없습니다. 승인된 실제 기기 및 운영 서명 검증 시험은 **미실행**입니다.

Windows PowerShell 확인: `npm.cmd install`, `npm.cmd run build`, `npm.cmd run decider:test`, `npm.cmd run detect:test`, `npm.cmd run bundle`. 웹앱에서는 로그인 전 자료 없음 → 승인 요청 후 대기 상태 → 서버 승인 시에만 화면 표시 순으로 확인합니다. 서버에서 승인되지 않은 요청의 직접 API 접근 차단은 별도 보완 필요합니다. 실행하지 않은 테스트는 미실행입니다.

### 11단계 채점 피드백 수정
- `public/index.html`의 로그인 토큰과 사용자 이메일을 브라우저 저장소가 아닌 페이지 메모리 변수로만 유지합니다. 승인 조회, 메모 요청, 보안 조회, 로그아웃 및 재로그인 흐름에서 같은 메모리 토큰을 사용합니다. 새로고침 시 재로그인이 필요합니다.
- `public/manifest.webmanifest` JSON 파싱과 앱 이름 `BYTE BACK 보안 자료실`, 시작 경로 `/`, scope `/`, standalone 설정을 확인했습니다. **배포 후** `https://choi-bujang-secret-vault-five-kappa.vercel.app/manifest.webmanifest`에서 200 응답과 JSON 내용이 표시되는지 직접 확인해야 합니다(배포 응답 미확인).
- 서버에서 승인 상태 `approved`를 반환할 때만 기존 메모 화면을 표시하는 흐름은 유지합니다. 기기 승인 및 실제 화면 확인은 미실행입니다.


## 12단계 저장점 — 탈환 작전실과 실측 증거

- 11단계 실제 심판 통과는 학생이 확인했습니다. 1~11단계 메모·인증·기기 승인·판정·탐지·복구 기능을 보존합니다.
- 작전실 UI는 기존 `public/index.html`에 포함되며, 관리자에게만 `GET /api/operations`를 통해 서버에서 확인한 최근 5분 `security_events` 사건 수, 기기 승인 상태별 수, 비공개 복구 사본의 조회 가능 여부를 표시합니다. 메모 본문·기기 키·토큰·소유자 식별자는 반환하지 않습니다.
- 학생 판정기 규칙은 `src/decider.mjs`의 `RULE_IDS`를 읽어 표시합니다. 실제 ALEPH SDP 엔진의 판정 호출·회수·복구 실행 성공을 추정하지 않습니다. 복구 버전은 현재 시점 스냅샷이며 사전 침해 백업이라고 주장하지 않습니다.
- **제공 엔진:** ALEPH SDP 엔진(심판·운영 측 제공). **학생 구현:** `src/decider.mjs`, `src/detect.mjs`, `api/`, `public/`, 정책 및 회귀 점검 문서. 엔진 자체는 학생 저장소에 포함되지 않습니다.
- 회귀 점검 표: 무인증 조회 401, 로그인 후 본인 조회 200, 타인 메모 조회·수정 404, 비인가 사건 기록, 미등록 기기 deny, 복합 이상 접속 step_up, 구역 밖 조회 deny, 조회 폭주 회수 제안, 단일 메모 복구의 ID·소유자·해시 일치, 승인 전 화면 차단 및 승인 후 화면 허용. 표의 **기대 결과는 실측 결과가 아닙니다.** 각 시험을 실행한 경우에만 요청 ID, 확인 시각(ISO-8601), 실제 HTTP 응답/판정, 기대값과의 일치 여부를 기록합니다. 현재 총공세 **41종 모두 미실행**, 통과 0건(미실행은 실패 판정 아님).
- 재현 절차: `git clone https://github.com/hongbin9305/choi-bujang-secret-vault.git` → `cd choi-bujang-secret-vault` → `npm install` → `npm run build` → `npm run decider:test` → `npm run detect:test` → `npm run bundle`. 마지막 명령은 깨끗한 Git 상태·유효한 origin·로컬 `bundle-notes.json`이 필요합니다. `artifacts/submission.json`과 `bundle-notes.json`은 커밋하지 않습니다.
- 실행/배포: Vercel에 GitHub `main`을 연결하고 `npm run build`로 `public/`을 배포합니다. Supabase 환경변수는 Vercel 비밀 설정에만 저장합니다. 앱 주소는 `aleph.config.json`의 `publicAppUrl`을 사용합니다.
- 중지: Vercel에서 해당 프로젝트 배포를 중단하거나 이전 검증 배포로 롤백합니다. DB를 임의로 삭제하지 않습니다.
- 복구: 10단계 README의 사본 재검증 → 버전·diff·변경 범위 사전 확인 → 승인된 시험 정책만 복원 순서를 따릅니다. 한 건의 메모만 `POST /api/restore/note`로 복구하고 ID·소유자·내용 SHA-256 해시를 각각 대조합니다. 사본 부재·검증 실패 시 중단합니다. 실복구 시험은 미실행입니다.
- 현재 12단계 새 API·UI의 운영 배포 및 41종 실측, `npm run bundle` 실행은 **미실행**입니다. 로컬 테스트를 심판 결과로 기재하지 않습니다.


## 보너스 xdr-01 저장점 — 무차별 로그인 경보

- 원본 Wazuh 경보 `xdr/fixtures/brute-force.json`은 수정하지 않았습니다. `xdr/brute-force/read-alerts.mjs`는 시각·출발 주소·계정·규칙 수준·설명만 추출하며 인증 비밀값을 반환하지 않습니다.
- MITRE ATT&CK T1110 및 T1110.003에 근거한 패턴은 `patterns.json`에 정리했습니다. `decide.mjs`는 외부 import, 파일 접근, 네트워크 요청 없이 개별 경보를 `block`(confidence >= 0.85), `alert`(>= 0.5), `record`로 분류합니다.
- `respond.mjs`는 고확신 차단 후보만 만료 시각·근거 경보 ID와 함께 `xdr/deny-rules.json`에 저장하고, 알림을 `xdr/alerts.log`에 추가합니다. 기존 ZTNA `src/decider.mjs` 규칙은 변경하지 않았습니다. **실제 엔진에 후보 규칙 적용은 미연결·미실행**입니다.
- fixture 28건을 동일 판단 조건으로 분류한 `xdr/brute-force/result.json`: **block 6, alert 3, record 19, 정상 이벤트 block 0**. 원본 경보의 비밀값은 결과에 포함하지 않습니다. 로컬 `npm run xdr:run -- brute-force` 실행은 이 환경의 GitHub 접근 제한으로 **미실행**이며, 저장된 결과와 실제 Node 실행 결과가 일치하는지 재확인이 필요합니다.
- 확인 명령: `npm run xdr:run -- brute-force`; `xdr/brute-force/result.json`의 counts 및 bf-20~bf-28이 record인지 확인합니다. 정상 이벤트가 block이면 해당 조건을 보수적으로 수정합니다.


## 보너스 xdr-02 저장점 — 웹 주입 공격 탐지

- `xdr/web-injection/decide.mjs`는 MITRE ATT&CK T1190 기반 독립형 판단 모듈이며 외부 import 및 파일 입출력이 없습니다.
- `patterns.json`에 SQL·스크립트·경로 이탈·명령 구분자 반복 패턴과 근거를 기록했습니다.
- `read-alerts.mjs`는 원본 경보를 수정하지 않고 확인용 필드만 추출합니다.
- `respond.mjs`는 10분 만료되는 별도 차단 후보 규칙과 알림 로그를 작성하며 기존 ZTNA 정책은 수정하지 않습니다.
- 사용자 로컬 실행 `npm.cmd run xdr:run -- web-injection` 결과: block 8 / alert 9 / record 9, 정상 이벤트 차단 0건(2026-10-15 확인). 실제 심판 채점은 별도입니다.
- Windows PowerShell 재실행: `npm.cmd run xdr:run -- web-injection`; 결과: `xdr/web-injection/result.json`.
