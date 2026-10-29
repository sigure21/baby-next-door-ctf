# 의도치 않은 풀이 점검

## 현재 확인한 경계

- backend port는 compose에서 `expose`만 사용하고 host에 publish하지 않음
- gateway 프로세스에는 `FLAG` 환경 변수가 없음
- `/internal/*`를 gateway가 직접 route하지 않음
- relay는 raw path를 `/public/*` 아래로만 매핑
- relay path의 `%`, `..`, `//`, backslash, absolute-form target을 거부
- ticket은 정확히 32자리 lowercase hex만 허용하고, window 발급 시 해당 client TCP connection에 binding
- mailbox는 최대 1024개, TTL 90초, one-shot read
- route window는 TTL 5분, one-shot carrier, connection-local WeakMap state
- body는 8 KiB, request target은 768 bytes로 제한
- middleware node는 process 시작마다 무작위이며 4개 이하 또는 공개 source map의 정적 `middleware` token은 우회 실패
- HTTP header name의 대소문자는 Node가 표준대로 동일하게 처리
- POST/GET chunked, OPTIONS/Content-Length, 잘못된 trailer, preload worker는 side effect 없음
- `103 Early Hints`의 window/session/worker는 최종 204 응답 header나 body에 반복하지 않음
- result는 같은 connection state의 session을 backend에 주입해야만 조회 가능
- deployment별 `WINDOW_SIGNING_KEY` capability가 window/session/ticket/worker를 backend에서 다시 결합 검증
- 명령 실행, 파일 읽기, 임의 URL fetch 기능 없음
- guest JWT는 process 시작 시 생성한 256-bit HMAC key를 사용하며 `alg:none`과 source-map fallback secret이 실패함
- `/admin/flag`의 값은 의도적으로 scoreboard에서 거부할 honey canary이며 실제 FLAG와 무관

## 배포 후 다시 확인할 항목

- [ ] 외부에서 backend `4000/tcp`에 직접 접속할 수 없음
- [ ] 플랫폼 로그와 error page에 `FLAG`가 나타나지 않음
- [ ] image history, environment inspection API가 참가자에게 노출되지 않음
- [ ] L7 proxy가 103, same-connection affinity, chunk trailer 또는 payload를 제거하지 않음
- [ ] `healthcheck.mjs`, `protocol-regression.mjs`, `solve.mjs` 모두 외부 경로에서 성공
- [ ] `/api/relay/%2e%2e/...`, double encoding, absolute URI, backslash 변형이 차단됨
- [ ] Host 조작만으로 backend route가 바뀌지 않음
- [ ] mailbox ticket brute force가 현실적인 요청량에서 불가능하고 rate limit이 적용됨

## 의도된 false leads

- 로그인 화면은 비밀번호 추측 대상이 아닙니다.
- 공개 ping은 backend 주소나 flag를 반환하지 않습니다.
- 공개 HTML/JS/dashboard에 정확한 vulnerable version이나 CVE 식별자가 없음
- guest JWT, source map의 개발용 secret, admin API는 인증 우회와 JWT 위조를 혼동하게 하는 방어 심층화 함정입니다.
- source map의 정적 middleware 이름은 실제 process-local route node가 아닙니다.
- 103의 `rel=preload` Link는 stale worker이고 `rel=preconnect`만 활성 worker입니다.
- static `/internal/export`는 성공처럼 보이는 legacy worker지만 mailbox를 쓰지 않습니다.
- `/admin/flag`는 1단계 성공을 확인시키지만 최종 제출은 거부되는 honey canary입니다.

false lead는 풀이를 방해할 뿐 별도 취약점이 되면 안 됩니다. 배포 플랫폼이 추가하는 debug endpoint, source map, metrics endpoint를 별도로 검사하십시오.
