# XSS (Cross-Site Scripting)

사용자가 보낸 값을 이스케이프 없이 HTML에 넣으면, 값 안의 `<script>`가 다른 사용자의 브라우저에서 실행된다. 공격자는 그 스크립트로 쿠키를 빼내거나 페이지를 조작한다.

글: [XSS — 저장형과 반사형, 출력 이스케이프와 CSP](https://sgom.github.io/posts/xss-basics/)

## 무엇을 보이나

댓글을 되비추는 페이지를 세 방식으로 둔다. 모두 같은 댓글 `<script>document.title='XSS'</script>`를 받는다.

| 경로 | 출력 방식 |
|---|---|
| `/vuln` | 입력을 그대로 HTML에 넣는다 (취약) |
| `/safe` | `<`, `>`, `&`, `"`, `'`를 HTML 엔티티로 이스케이프 |
| `/csp` | 입력은 그대로 넣되 `Content-Security-Policy` 헤더로 인라인 스크립트를 막는다 |

## 실행

두 단계다. 1단계는 의존성 없이 돌고, 2단계는 실제 브라우저가 필요하다.

### 1단계: 렌더된 HTML 보기 (의존성 없음)

서버가 각 경로에 내려 준 HTML에서 `#comment` 안을 꺼내 보인다. 입력이 살아 있는 `<script>` 태그로 남는지, 텍스트로 바뀌는지가 드러난다.

```sh
node xss.mjs
```

```
Node.js v24.15.0
입력한 댓글: <script>document.title='XSS'</script> 

취약 (/vuln)
  #comment 안의 HTML: <script>document.title='XSS'</script>
  CSP 헤더: (없음)

수정 (/safe)
  #comment 안의 HTML: &lt;script&gt;document.title=&#39;XSS&#39;&lt;/script&gt;
  CSP 헤더: (없음)

CSP (/csp)
  #comment 안의 HTML: <script>document.title='XSS'</script>
  CSP 헤더: default-src 'self'; script-src 'self'
```

`/vuln`과 `/csp`는 `<script>`가 그대로 HTML에 들어갔고, `/safe`는 `&lt;script&gt;`로 바뀌어 더는 태그가 아니다.

### 2단계: 실제 실행 확인 (Playwright)

HTML에 `<script>`가 남는 것과 브라우저가 그것을 실행하는 것은 다른 문제다. 헤드리스 Chromium으로 각 페이지를 열어, 주입한 스크립트가 `document.title`을 `XSS`로 바꿨는지 측정한다.

```sh
npm install
npx playwright install chromium
node check.mjs
```

```
입력한 댓글: <script>document.title='XSS'</script> 

취약 (/vuln)
  스크립트 실행됨: true
수정 (/safe)
  스크립트 실행됨: false
CSP (/csp)
  스크립트 실행됨: false
  콘솔 오류: Executing inline script violates the following Content Security Policy directive 'script-src 'self''. Either the 'unsafe-inline' keyword, a hash ('sha256-9tN3Fi2eH7HFcFPIe+aXzmbILbxcEAuOFIt4LTGBsGA='), or a nonce ('nonce-...') is required to enable inline execution. The action has been blocked.
```

`/vuln`만 스크립트가 실행됐다. `/safe`는 태그가 텍스트라 실행되지 않고, `/csp`는 HTML에 태그가 있어도 CSP가 인라인 스크립트를 차단해 콘솔 오류를 남긴다.

## 읽는 법

- 1단계가 원인(입력이 live HTML로 남는가), 2단계가 결과(브라우저가 실행하는가)다.
- `/safe`는 출력 이스케이프 하나로 막는다. 근본 방어다.
- `/csp`는 이스케이프를 빠뜨렸어도 CSP가 한 겹 더 막는 것을 보인다. 이스케이프를 대신하는 것이 아니라 겹쳐 두는 방어다.

## 한계

반사형(reflected) XSS 한 형태만 보인다. 입력이 DB에 저장됐다가 나중에 다른 사용자에게 나가는 저장형(stored)은 경로가 길 뿐 출력 지점의 문제는 같다. 페이로드는 `document.title`을 바꾸는 무해한 것으로, 실제 공격은 쿠키 탈취나 요청 위조를 노린다. CSP는 인라인 스크립트 차단만 보이고, `script-src`의 다른 우회는 다루지 않는다.

## 파일

- `xss.mjs`: 서버와 1단계 데모. 서버는 `127.0.0.1`의 임의 포트에 뜬다. `check.mjs`가 서버를 재사용하도록 `server`를 export 한다.
- `check.mjs`: Playwright로 2단계를 측정한다.
