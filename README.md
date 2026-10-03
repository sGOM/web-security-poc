# web-security-poc

웹 서버를 만들 때 주의할 취약점을 하나씩 재현하는 PoC 모음. [기술 블로그](https://sgom.github.io)의 보안 글마다 폴더 하나가 대응한다.

## 원칙

- **로컬에서만 돈다.** 모든 서버는 `127.0.0.1`에 뜨고, 공격 스크립트의 대상도 그 서버뿐이다. 외부 주소를 향하는 코드는 없다.
- **취약한 쪽과 고친 쪽을 나란히 둔다.** 같은 공격을 양쪽에 보내 결과가 갈리는 것을 출력으로 확인한다.
- **스크립트 하나로 재현된다.** 폴더의 README에 적힌 명령을 그대로 실행하면 README에 실린 출력이 나온다.

이 저장소의 코드는 취약점을 설명하려고 일부러 취약하게 짠 것이다. 다른 곳에 가져다 쓰지 않는다.

## 목록

| 폴더 | 취약점 | 글 |
|---|---|---|
| [`csrf/`](./csrf) | CSRF (Cross-Site Request Forgery) | [CSRF — 쿠키가 자동으로 실리는 것이 왜 문제인가](https://sgom.github.io/posts/csrf-basics/) |
| [`sql-injection/`](./sql-injection) | SQL 인젝션 | [SQL 인젝션 — 문자열로 이어 붙인 쿼리가 명령이 되는 과정](https://sgom.github.io/posts/sql-injection/) |
| [`xss/`](./xss) | XSS (Cross-Site Scripting) | [XSS — 저장형과 반사형, 출력 이스케이프와 CSP](https://sgom.github.io/posts/xss-basics/) |
| [`ssrf/`](./ssrf) | SSRF (Server-Side Request Forgery) | [SSRF — 서버가 대신 요청할 때 내부 주소에 닿는 것](https://sgom.github.io/posts/ssrf-basics/) |
| [`path-traversal/`](./path-traversal) | 경로 조작 (Path Traversal) | [경로 조작 — ../로 공개 디렉터리를 벗어나는 파일 읽기](https://sgom.github.io/posts/path-traversal/) |
| [`idor/`](./idor) | IDOR (접근 제어 누락) | [IDOR — 로그인은 확인하고 소유자는 확인하지 않을 때](https://sgom.github.io/posts/idor/) |

## 실행 환경

폴더마다 README에 적는다. 대부분 Node.js 24의 표준 라이브러리만으로 돈다. 일부 폴더(`xss/`)는 실제 브라우저 확인에 Playwright를 쓴다. 그 경우 `npm install`로 받는다.
