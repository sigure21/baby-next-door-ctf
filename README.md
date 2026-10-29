# Baby Next Door

겉보기 난이도는 `Easy`지만, 실제 의도 풀이는 두 개의 서로 다른 HTTP 신뢰 경계를 연결해야 하는 블랙박스 웹 CTF입니다.

- 1단계: `CVE-2025-29927`에서 영감을 받은 Middleware 인증 우회
- 2단계: 같은 TCP 연결에서 `103 Early Hints`의 one-shot window와 동적 worker 관찰
- 3단계: HMAC chunk trailer로 무장한 `CVE-2026-29057`-inspired rewrite 요청 스머글링
- 4단계: 연결 affinity가 걸린 blind result를 한 번만 회수

JWT, source map 개발 키·가짜 middleware 이름, Host 조작, path traversal, stale worker, 잘못된 HTTP method/framing, 제출 불가 honey flag를 의도된 함정으로 포함합니다. 정적 CVE payload는 매 부팅마다 달라지는 route node와 매 연결마다 달라지는 window/session/worker 때문에 실패합니다.

AI를 절대 차단한다고 보장할 수는 없습니다. 이 설계의 목표는 정적 LLM 답변·CVE 검색·복붙 exploit을 무효화하고, 실제 black-box 관찰과 stateful raw HTTP 구현을 강제하는 것입니다. 참가자에게 소스나 private 저장소 접근권을 주면 이 성질은 사라집니다.

이 구현은 실제 Next.js 취약 패키지를 포함하지 않습니다. 공개된 취약점의 핵심 조건을 표준 Node.js만으로 축소 모델링하여, 추가 CVE나 패키지 공급망 상태에 따라 풀이가 흔들리지 않도록 만든 교육용 시뮬레이터입니다. 따라서 **실제 제품의 1:1 PoC라고 주장하면 안 됩니다.**

## 빠른 실행

```powershell
cd challenges/baby-next-door
$env:FLAG = 'flag{use_a_real_random_event_flag}'
$env:WINDOW_SIGNING_KEY = node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))"
docker compose up -d --build
node tests/healthcheck.mjs
node tests/protocol-regression.mjs
node solver/solve.mjs
```

기본 접속 주소는 `http://127.0.0.1:8080`입니다. 포트는 `CHALLENGE_PORT` 환경 변수로 바꿀 수 있습니다.

종료:

```powershell
$env:FLAG = 'flag{unused_for_shutdown}' # 새 shell에서 down만 실행할 때 필요한 compose placeholder
$env:WINDOW_SIGNING_KEY = '0000000000000000000000000000000000000000000000000000000000000000'
docker compose down --remove-orphans
```

## 디렉터리

```text
handout/README.md          참가자 공개 지문
src/gateway.mjs           프런트/Middleware/rewrite 동작 모델
src/backend.mjs           외부 미노출 backend와 ticket mailbox
tests/healthcheck.mjs      정상 동작 및 단순 우회 차단 검사
tests/protocol-regression.mjs
solver/raw-http.mjs        1xx 응답을 보존하는 raw HTTP/1.1 client
solver/solve.mjs           출제자용 동적 기준 exploit
organizer/WRITEUP.md       전체 풀이와 CVE 매핑
organizer/DEPLOY.md        배포·격리 체크리스트
organizer/HINTS.md         시간차/감점 공개용 힌트
organizer/UNINTENDED.md    의도치 않은 풀이 점검표
```

## 공식 근거

- [Next.js Middleware Authorization Bypass — GHSA-f82v-jwr5-mffw / CVE-2025-29927](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw)
- [Vercel 사후 분석](https://vercel.com/blog/postmortem-on-next-js-middleware-bypass)
- [Next.js rewrite request smuggling — GHSA-ggv3-7p47-pfv8 / CVE-2026-29057](https://github.com/vercel/next.js/security/advisories/GHSA-ggv3-7p47-pfv8)
- [NVD CVE-2026-29057](https://nvd.nist.gov/vuln/detail/CVE-2026-29057)

## 안전 범위

이 문제는 소유한 로컬/행사 인프라에서만 실행하십시오. backend 포트는 publish하지 않으며, 호스트 마운트·명령 실행·외부 URL fetch 기능도 없습니다. 실제 인터넷 대상에서 동일한 기법을 시도해서는 안 됩니다.
