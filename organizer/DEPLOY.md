# 배포 체크리스트

## 필수

1. 이벤트별 무작위 flag를 환경 변수로 주입합니다.

   ```powershell
   $env:FLAG = 'flag{replace_with_a_random_event_secret}'
   $env:WINDOW_SIGNING_KEY = node -e "process.stdout.write(require('crypto').randomBytes(32).toString('hex'))"
   docker compose up -d --build
   ```

2. host에는 gateway의 `3000/tcp`만 publish합니다. backend의 `4000/tcp`를 절대 publish하지 않습니다.
3. 참가자에게는 `handout/README.md`와 endpoint만 제공합니다. `src/`, `solver/`, `organizer/`, `tests/`, private GitHub 저장소, container image pull 권한을 제공하지 않습니다.
4. 외부에서 `node solver/solve.mjs`를 실행해 end-to-end로 확인합니다.
5. 기본 개발 flag 문자열이 실제 응답에 나오지 않는지 확인합니다.
6. scoreboard는 정규식/prefix가 아니라 실제 flag와의 **exact match**로 채점하고, honey canary `flag{stage_one_is_only_a_canary}`가 거부되는지 제출 테스트합니다.
7. process-local routing node 공유를 피하고 연결 고갈의 blast radius를 줄이기 위해 팀별 독립 인스턴스로 배포합니다.

## 프록시 주의

이 문제는 HTTP/1.1 keep-alive affinity, `103 Early Hints`, chunk framing, trailer가 모두 입력입니다. L7 reverse proxy, CDN, HTTP/2 termination, WAF가 요청을 decode/re-encode하거나 연결을 바꾸면 의도 풀이가 사라질 수 있습니다.

- 가장 단순한 배포는 Docker publish port를 참가자에게 직접 제공하는 방식입니다.
- 앞단이 꼭 필요하면 HTTP 메시지를 정규화하지 않는 L4 TCP passthrough를 사용합니다.
- 반드시 참가자와 동일한 외부 경로에서 solver를 실행합니다.
- 원격 endpoint는 `CHALLENGE_URL=http://host:port`로 지정할 수 있으며 solver가 raw TCP 대상도 여기서 파생합니다. HTTPS endpoint는 지원하지 않습니다.

## 격리

compose 기본값은 다음을 적용합니다.

- non-root `node` 사용자
- read-only root filesystem
- Linux capabilities 전체 제거
- `no-new-privileges`
- host volume mount 없음
- backend는 internal Docker network에만 연결
- 외부 URL fetch 및 OS command 실행 기능 없음

compose에는 컨테이너당 CPU 0.5, memory 128 MiB, PID 64, file descriptor 1024와 애플리케이션 connection 상한을 설정했습니다. 행사 ingress에도 source별 connection/rate limit을 추가하십시오.

## 기능 검사

```powershell
node tests/healthcheck.mjs
node tests/protocol-regression.mjs
node solver/solve.mjs
```

세 명령이 모두 성공해야 합니다. protocol regression은 다른 연결, POST/GET chunked, OPTIONS/Content-Length, 잘못된 trailer, preload decoy worker가 모두 실패하고, same-connection window + 올바른 trailer + OPTIONS/chunked만 성공하는지 확인합니다.

## 초기화

mailbox는 backend 메모리에만 있고 각 entry는 90초 뒤 만료되며 한 번 읽으면 삭제됩니다. 완전 초기화가 필요하면 컨테이너를 재시작합니다.

```powershell
docker compose restart backend gateway
```
