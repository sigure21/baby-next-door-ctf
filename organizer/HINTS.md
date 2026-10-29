# 단계별 힌트

초기 handout에 공개하지 말고, 요청 또는 경기 진행도에 따라 한 단계씩 공개합니다.

1. **-10점** — 로그인 토큰보다 302 응답의 routing trace를 먼저 보라. source map의 middleware 이름은 믿지 마라.
2. **-20점** — 내부 재귀 호출 헤더는 맞지만 value는 인스턴스마다 다르다. trace의 node와 budget을 그대로 표현하라.
3. **-30점** — `client-compat.log`에서 fetch와 wiretap이 같은 요청을 어떻게 다르게 관찰했는지 비교하라. 최종 응답만 보면 필요한 metadata가 사라진다.
4. **-40점** — `dispatcher.audit`의 두 Link와 `wire-v2.stderr`의 connection ID를 함께 보라. 오래된 incident 값은 복사하는 값이 아니라 현재 응답에서 다시 얻어야 하는 형식 예시다.
5. **-50점** — `.old` 설정은 boot 과정에서 무시됐다. schema 2의 `mac.*` 행과 method/framing 실험 행렬을 순서대로 조립하라.
6. **-60점** — HTTP/1.1 chunk trailer를 보존하는 raw client가 필요하다. 현재 103에서 받은 네 metadata를 inner worker 요청에 전달하고, 같은 connection의 one-shot result를 확인하라.
