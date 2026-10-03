# OAuth2 state 파라미터 CSRF (로그인 CSRF / 계정 바인딩)

OAuth2 인가 코드 흐름에서 클라이언트가 콜백의 `state` 파라미터를 검증하지 않으면 로그인 CSRF 가 생긴다. 공격자가 자기 계정의 인가 `code` 를 미리 얻어, 그 `code` 를 담은 위조 콜백 URL 을 피해자가 열게 만든다. 클라이언트가 콜백의 출처를 묶는 `state` 를 보지 않으면 피해자의 클라이언트 세션이 공격자 계정에 묶인다. 그 뒤 피해자가 올리는 데이터는 공격자 계정에 쌓인다. 핵심 방어는 로그인 시작 때 만든 무작위 `state` 를 세션에 저장해 두고, 콜백의 `state` 가 그와 일치할 때만 `code` 를 교환하는 것이다.

글: [OAuth2 기본개념 — 네 역할과 토큰 발급 흐름](https://sgom.github.io/posts/oauth2-basics/)

## 무엇을 보이나

한 프로세스가 작은 인가 서버와 클라이언트를 함께 띄운다. 전부 `127.0.0.1`. 인가 코드 흐름을 메모리로 축약한다.

- 클라이언트 `/login` 이 세션을 만들고 무작위 `state`(`randomUUID`)를 세션에 저장한 뒤 인가 서버 `/authorize` 로 보낸다(`client_id`, `redirect_uri`, `state`).
- 인가 서버 `/authorize` 가 로그인된 사용자에게 `code` 를 발급해 `redirect_uri?code=...&state=...` 로 되돌린다(받은 `state` 를 그대로 echo).
- 클라이언트 콜백이 `code` 를 `/token` 으로 서버 대 서버 교환해 그 사용자로 세션을 연다.

콜백이 두 가지다.

- `/vuln/callback`: `state` 를 보지 않고 들어온 `code` 를 그대로 교환해 세션을 연다 (취약).
- `/safe/callback`: 로그인 시작 때 세션에 저장한 `state` 와 콜백의 `state` 가 일치할 때만 교환한다. `state` 가 없거나 다르면 400 으로 거부 (고침).

세션 상태는 `/me` 로 읽고, `/note` 는 세션이 묶인 계정 앞으로 데이터를 쌓는다.

공격 시나리오를 한 실행에서 재현한다.

1. 정상 흐름: 피해자 `alice` 가 자기 계정으로 로그인한다. `state` 가 일치하므로 양쪽 다 통과하고 세션이 `alice` 에 묶인다.
2. 공격자가 인가 서버에 자기(`attacker`) 계정으로 `/authorize` 를 타 콜백 직전까지 가서, 돌려받은 Location 에서 자기 `code` 를 가로채 위조 콜백 URL 을 손에 쥔다. 이 URL 의 `state` 는 공격자가 정한 값이라 피해자 세션이 저장한 `state` 와 다르다.
3. 이미 `alice` 로 로그인된 세션을 든 피해자가 위조 콜백을 연다.
   - 취약: `state` 를 안 보므로 공격자 `code` 를 그대로 교환한다. 세션이 `alice` -> `attacker` 로 다시 묶인다. 이어서 피해자가 올린 메모가 공격자 계정에 쌓인다.
   - 고침: `state` 불일치(공격자가 정한 값)로 400 거부, `state` 가 아예 없는 콜백도 400 거부. 세션은 `alice` 그대로다.

콜백에서 `state` 를 세션에 저장해 둔 값과 대조하는 부분이 방어의 전부다.

아래는 `oauth2-state-csrf.mjs` 의 두 콜백 핸들러를 그대로 옮긴 것이다. 취약한 쪽은 `state` 를 읽지도 않고 들어온 `code` 를 바로 `exchange` 한다.

```js
  // 취약: state 를 검증하지 않고 code 를 그대로 교환해 세션을 연다.
  if (p === '/vuln/callback') {
    const sid = parseCookie(req).sid;
    const sess = clientSessions.get(sid);
    if (!sess) { res.writeHead(401).end('no session'); return; }
    const code = url.searchParams.get('code');
    // state 를 보지 않는다. 들어온 code 를 그대로 교환한다.
    const who = await exchange(code);
    if (!who) { res.writeHead(400).end('exchange failed'); return; }
    sess.boundAccount = who;
    res.writeHead(200, { 'Content-Type': 'application/json' })
      .end(JSON.stringify({ bound: who }));
    return;
  }
```

고친 쪽은 로그인 시작 때 세션에 저장한 `state` 와 콜백의 `state` 가 일치할 때만 교환한다. 없거나 다르면 400 으로 거부한다.

```js
  // 고침: 로그인 시작 때 세션에 저장한 state 와 콜백의 state 가 일치할 때만 교환한다.
  if (p === '/safe/callback') {
    const sid = parseCookie(req).sid;
    const sess = clientSessions.get(sid);
    if (!sess) { res.writeHead(401).end('no session'); return; }
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    if (!state || state !== sess.pendingState) {
      res.writeHead(400, { 'Content-Type': 'application/json' })
        .end(JSON.stringify({ error: 'state mismatch', expected: sess.pendingState, got: state }));
      return;
    }
    sess.pendingState = null; // 1회용
    const who = await exchange(code);
    if (!who) { res.writeHead(400).end('exchange failed'); return; }
    sess.boundAccount = who;
    res.writeHead(200, { 'Content-Type': 'application/json' })
      .end(JSON.stringify({ bound: who }));
    return;
  }
```

## 실행

Node.js 24. 의존성 없음. 서버는 `127.0.0.1` 에만 뜬다.

```sh
node oauth2-state-csrf.mjs
```

```
v24.15.0
OAuth2 데모 서버(인가 서버+클라이언트): http://127.0.0.1:51825

========== 1. 정상 흐름 (state 일치) ==========
피해자 alice 가 자기 계정으로 로그인한다. 양쪽 다 통과해야 한다.
[취약] 콜백 200 {"bound":"alice"}  -> {"status":200,"body":"{\"boundAccount\":\"alice\"}"}
[고침] 콜백 200 {"bound":"alice"}  -> {"status":200,"body":"{\"boundAccount\":\"alice\"}"}

========== 2. 공격자가 자기 계정의 code 를 미리 얻는다 ==========
공격자가 쥔 위조 콜백(취약용): /vuln/callback?code=1f8e22c4-cb20-4814-9e75-24d56bc6b9c7&state=attacker-chosen-state
공격자가 쥔 위조 콜백(고침용, state 불일치): /safe/callback?code=72ad0570-7bce-4be4-824d-9b74eabbe9c1&state=attacker-chosen-state
공격자가 쥔 위조 콜백(고침용, state 없음):   /safe/callback?code=01e28aa3-e31a-44ee-9082-59b84073fd64

========== 3. 피해자가 위조 콜백을 연다 ==========
피해자는 이미 자기 계정(alice)으로 로그인된 세션을 들고 있다.
위조 전 /me: 취약={"boundAccount":"alice"}, 고침={"boundAccount":"alice"}
피해자 세션에 저장된 state: null, 위조 콜백의 state: "attacker-chosen-state", 일치: false

[취약] 위조 콜백 응답: 200 {"bound":"attacker"}  (수용(세션이 공격자 code 로 재바인딩))
[취약] 위조 후 /me: 200 {"boundAccount":"attacker"}

[고침, state 불일치] 위조 콜백 응답: 400 {"error":"state mismatch","expected":null,"got":"attacker-chosen-state"}  (거부)
[고침, state 없음]   위조 콜백 응답: 400 {"error":"state mismatch","expected":null,"got":null}  (거부)
[고침] 위조 후 /me: 200 {"boundAccount":"alice"}

========== 결과 (측정값) ==========
취약: 세션이 alice -> attacker 로 다시 묶였다.
고침: 세션이 alice 그대로다 (위조 콜백 400/400).
클라이언트가 계정별로 쌓은 메모(피해자가 올린 것이 누구 계정에 들어갔나):
  attacker: ["취약 세션에서 올린 메모"]
  alice:    ["고침 세션에서 올린 메모"]
```

포트 번호는 실행마다 달라진다(`listen(0)`). 인가 `code` 는 `randomUUID()` 라 매 실행 바뀐다. 위 출력의 포트 `51825` 와 `1f8e22c4-...` 같은 code 값은 그 한 번의 실행에서 나온 값이다. `state: null` 은 피해자가 정상 로그인을 마치며 저장된 state 를 소비했기 때문이고(1회용), 그래서 뒤이은 위조 콜백의 state 와 어차피 일치하지 않는다. 바뀌지 않는 것은 취약/고침의 콜백 상태 코드(200 대 400), 세션이 묶인 계정, 메모가 들어간 계정이다.

## 읽는 법

- 정상 흐름에서는 피해자가 시작한 로그인의 `state` 가 콜백에 그대로 돌아오므로 양쪽 다 통과하고 세션이 `alice` 에 묶인다.
- 위조 콜백은 공격자가 시작한 흐름의 `code` 와 `state` 를 담는다. 피해자 세션이 저장한 `state` 와는 무관한 값이다.
- 취약한 쪽은 `state` 를 보지 않으므로 공격자 `code` 를 그대로 교환한다. 세션이 `attacker` 로 다시 묶이고(`/me` 가 `attacker`), 이어서 피해자가 올린 메모가 `attacker` 계정에 쌓인다. 공격자는 자기 계정으로 들어가 피해자가 올린 데이터를 본다.
- 고친 쪽은 콜백의 `state` 가 세션에 저장한 값과 다르므로 400 으로 거부한다. 세션은 `alice` 그대로이고 피해자가 올린 메모는 자기 계정(`alice`)에 들어간다.

## 한계

- **`state` 의 CSRF 방지 역할만 보인다.** 실제 IdP, PKCE, 토큰 서명·만료·저장, `redirect_uri` 정확 일치 검증 같은 OAuth2 보안의 다른 축은 다루지 않는다. 로그인·토큰 교환은 메모리로 축약했고 흐름만 드러낸다.
- **PKCE 는 다른 위협(코드 가로채기)을 겨냥하지만 이 주입 공격도 함께 막는다.** PKCE 의 주 목적은 전송 중 가로챈 `code` 를 공격자가 토큰으로 바꾸지 못하게 막는 것이다(`code_verifier` 미소지). 다만 인가 서버가 PKCE 를 지원하면 이 PoC 가 보이는 code 주입도 교환 단계에서 실패한다. RFC 9700 §2.1 은 그 경우 PKCE 가 제공하는 CSRF 방어에 의존해도 된다(MAY)고 적는다. 이 PoC 에는 PKCE 가 없어 `state` 가 유일한 방어다. 두 방어의 범위는 겹치되, 책임의 뿌리는 "콜백의 출처를 묶는다"(state)와 "가로챈 code 를 무력화한다"(PKCE)로 나뉜다.
- **인가 서버의 로그인 사용자(`as_user`)는 쿼리로 축약했다.** 실제 서버는 인가 서버 자신의 세션 쿠키에서 읽는다. 공격자가 어떻게 피해자에게 위조 콜백 URL 을 열게 하는지(메일·페이지 삽입 등 실제 전달 경로)는 재현하지 않는다. 이미 피해자가 그 URL 을 연다는 전제에서 돈다.
- **쿠키 전달은 클라이언트가 직접 `Cookie` 헤더를 붙여 흉내 낸다.** 브라우저의 쿠키 저장소나 `Set-Cookie` 자동 반영, 크로스 사이트 요청의 쿠키 동반 여부는 재현하지 않는다. 측정하는 것은 서버의 세션 바인딩과 응답 상태뿐이다.
- 축약을 위해 콜백은 로그인된 세션을 재바인딩할 수 있게 두었다(취약 쪽에서 `alice` -> `attacker`). 실제 클라이언트의 계정 연동 구현은 다를 수 있으나, `state` 미검증이라는 뿌리는 같다.

## 파일

- `oauth2-state-csrf.mjs`: 인가 서버(`/authorize`, `/token`), 클라이언트(`/login`, `/vuln/callback`, `/safe/callback`, `/me`, `/note`), 공격 시나리오 데모를 한 파일에 담았다.
