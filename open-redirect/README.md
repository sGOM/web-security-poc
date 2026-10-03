# 오픈 리다이렉트 (Open Redirect)

로그인 뒤 원래 보던 페이지로 돌려보내려고 `?next=<경로>` 같은 파라미터를 받는 사이트가 많다. 그 값을 검증하지 않고 그대로 `Location` 헤더에 넣으면, 공격자는 자기 사이트 주소를 `next`에 넣어 피해자를 외부 피싱 페이지로 보낸다. 링크는 진짜 사이트의 로그인 주소라 피해자는 믿고 누른다.

글: [오픈 리다이렉트 — 로그인 뒤 ?next= 를 믿을 때](https://sgom.github.io/posts/open-redirect/)

## 무엇을 보이나

로그인 서버 하나가 `?next=`로 받은 주소로 302 리다이렉트한다. 실제 로그인은 생략하고 리다이렉트 결정만 보인다.

- `/vuln/redirect`: `next` 값을 검증 없이 그대로 `Location`에 넣는다 (취약)
- `/safe/redirect`: `next`가 같은 사이트 내부 경로일 때만 허용하고, 그 밖은 `/`로 돌린다 (고침)

같은 `next` 값을 양쪽에 보내 `Location`을 대조한다. 서버가 외부로 요청을 보내지는 않는다. `fetch(..., { redirect: 'manual' })`로 302를 따라가지 않고 `Location` 헤더만 읽는다.

안전 판정은 두 겹이다.

```js
function safeNext(next, base) {
  if (typeof next !== 'string') return '/';
  if (!next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\')) return '/';
  let resolved;
  try {
    resolved = new URL(next, base);
  } catch {
    return '/';
  }
  if (resolved.origin !== base) return '/';
  return next;
}
```

1. 반드시 슬래시 하나로 시작해야 하고 `//`나 `/\`로 시작하면 거절한다. 파서 동작에 기대지 않고 스킴 상대 URL과 역슬래시 우회를 먼저 걷어낸다.
2. `base`를 기준으로 파싱한 `origin`이 서버 자신과 같아야 한다. `javascript:` 같은 다른 스킴이나 외부 호스트는 여기서 걸린다.

## 실행

Node.js 24. 의존성 없음. 서버는 `127.0.0.1`에만 뜬다.

```sh
node open-redirect.mjs
```

```
$ node open-redirect.mjs
Node.js v24.15.0
로그인 서버: http://127.0.0.1:51702

next 값마다 취약/고침의 Location(302) 을 대조한다.

  next = "/dashboard"
    취약 /vuln/redirect -> 302 Location: /dashboard
    고침 /safe/redirect -> 302 허용

  next = "https://evil.example/phish"
    취약 /vuln/redirect -> 302 Location: https://evil.example/phish
    고침 /safe/redirect -> 302 거절 -> /

  next = "//evil.example"
    취약 /vuln/redirect -> 302 Location: //evil.example
    고침 /safe/redirect -> 302 거절 -> /

  next = "/\\evil.example"
    취약 /vuln/redirect -> 302 Location: /\evil.example
    고침 /safe/redirect -> 302 거절 -> /

  next = "/\t/evil.example"
    취약 /vuln/redirect -> 302 Location: /	/evil.example
    고침 /safe/redirect -> 302 거절 -> /

  next = "javascript:alert(1)"
    취약 /vuln/redirect -> 302 Location: javascript:alert(1)
    고침 /safe/redirect -> 302 거절 -> /
```

포트 번호는 실행마다 달라진다. `next` 값은 `JSON.stringify`로 찍어 백슬래시가 `/\\evil.example`처럼 이스케이프되어 보인다. `Location:` 줄은 실제 헤더 값이라 `/\evil.example`처럼 백슬래시 그대로 나온다.

## 읽는 법

- `/dashboard`: 같은 사이트 내부 경로. 양쪽 다 그대로 보낸다.
- `https://evil.example/phish`: 외부 절대 URL. 취약한 쪽은 `Location`에 그대로 넣어 피해자를 외부로 보낸다. 고친 쪽은 슬래시로 시작하지 않아 거절하고 `/`로 돌린다.
- `//evil.example`: 스킴 상대 URL. 브라우저는 `Location: //evil.example`를 현재 페이지와 같은 스킴(http/https)을 붙인 `http(s)://evil.example`로 해석해 외부로 나간다. 취약한 쪽은 그대로 넣는다. 고친 쪽은 `//`로 시작해 거절한다.
- `/\evil.example`: 역슬래시 우회. 브라우저와 WHATWG URL 파서는 `http(s)` 같은 특수 스킴에서 `\`를 `/`와 같게 다뤄 `/\evil.example`를 `//evil.example`로 본다. 결국 외부 호스트로 나간다. 취약한 쪽은 그대로 넣는다. 고친 쪽은 `/\`로 시작해 1단계에서 거절하고, 2단계의 `new URL(...).origin`도 `http://evil.example`로 풀려 거절한다.
- `javascript:alert(1)`: 슬래시로 시작하지 않아 1단계에서 거절한다. `new URL('javascript:alert(1)', base).origin`은 `null`이라 2단계로도 걸린다.

## 한계

- **브라우저의 실제 해석은 이 PoC가 측정하지 않는다.** `//evil.example`나 `/\evil.example`가 왜 외부로 나가는지는 브라우저가 스킴 상대 URL과 역슬래시를 해석하는 방식으로 설명했지만, PoC가 측정하는 것은 서버가 넣은 `Location` 헤더 값과 안전 판정 결과뿐이다. 302를 받은 브라우저가 어디로 가는지는 측정하지 않는다.
- **`javascript:` 스킴이 302 `Location`으로 실행되는지는 확인하지 않았다.** 확인한 것은 취약한 쪽이 그 값을 `Location`에 그대로 넣는다는 것뿐이다. 서버 리다이렉트의 `Location`에 담긴 `javascript:`는 일반적으로 브라우저가 실행하지 않는 것으로 알려져 있으나, 이 PoC로 검증하지 않았다. 실제 위험은 서버 리다이렉트보다 클라이언트 쪽에서 같은 값을 `location.href = next`나 `<a href>`에 다시 쓰는 경로에 있다. 그 경로도 재현하지 않는다.
- `next`를 쿼리 파라미터로만 받는다. 경로 조각이나 다른 헤더로 받는 변형, 인코딩을 여러 겹 씌운 우회(`%2f%2f` 등)는 다루지 않는다. 안전 판정은 디코딩된 값을 받는다는 전제에서 돈다.
- 고친 쪽은 유효한 내부 경로면 원래 `next`를 그대로 `Location`에 넣는다. 허용 목록(allowlist)으로 특정 경로만 받는 더 엄격한 방식은 보이지 않는다.

## 파일

- `open-redirect.mjs`: 로그인 서버, 안전 판정 함수, 데모를 한 파일에 담았다.
