# 세션 고정 (Session Fixation)

로그인 전부터 존재하던 세션 ID 를 로그인 뒤에도 그대로 쓰면, 공격자가 미리 심어 둔 세션 ID 로 피해자의 로그인 세션을 가로챈다. 공격자는 아직 로그인되지 않은 세션 ID 하나를 정해 피해자가 그 ID 를 쿠키로 들고 로그인하게 만든다. 로그인이 그 ID 를 그대로 둔 채 user 만 붙이면, 같은 ID 를 쥔 공격자가 로그인된 세션을 그대로 쓴다. 핵심 방어는 로그인 성공 시 세션 ID 를 새로 발급(regenerate)하는 것이다.

글: [세션 고정 — 로그인해도 세션 ID 가 그대로일 때](https://sgom.github.io/posts/session-fixation/)

## 무엇을 보이나

인메모리 세션 저장소(`sessionId -> { user }`) 하나를 둔 서버가 두 로그인 경로를 제공한다.

- `/vuln/login`: 로그인 성공 시 들어온 세션 ID 를 그대로 두고 그 세션에 user 를 붙인다 (취약)
- `/safe/login`: 로그인 성공 시 새 세션 ID 를 발급하고(`Set-Cookie` 로 새 ID) 옛 세션은 버린다 (고침)
- `/me`: 세션에 user 가 있을 때만 보이는 보호된 페이지. 없으면 401.

공격 시나리오를 한 실행에서 재현한다.

1. 공격자가 고정 세션 ID `ATTACKER-FIXED-SID` 를 정한다.
2. 피해자가 그 ID 를 쿠키로 들고 로그인한다(`Cookie: sid=ATTACKER-FIXED-SID`).
3. 피해자가 그 세션으로 로그인에 성공한다.
4. 공격자가 원래의 `ATTACKER-FIXED-SID` 로 `/me` 에 접근한다.

취약한 쪽은 4번에서 200 에 피해자 정보가 나오고, 고친 쪽은 401 이다.

로그인 시 세션 ID 를 새로 발급하는 부분이 방어의 전부다.

```js
if (req.method === 'POST' && url.pathname === '/safe/login') {
  const { user, pass } = await readJson(req);
  if (user !== USER || pass !== PASS) {
    res.writeHead(401).end('bad credentials');
    return;
  }
  // 고침: 로그인 성공 시 세션 ID 를 새로 발급하고 옛 세션은 버린다.
  sessions.delete(sid);                 // 로그인 전 세션 폐기
  const newSid = randomUUID();          // 새 세션 ID
  sessions.set(newSid, { user });
  res.writeHead(200, { 'Set-Cookie': `sid=${newSid}; HttpOnly; Path=/` }).end('ok');
  return;
}
```

취약한 쪽은 같은 자리에서 `sessions.set(sid, { user })` 로 들어온 ID 에 user 를 붙이고 그 ID 를 그대로 `Set-Cookie` 한다.

## 실행

Node.js 24. 의존성 없음. 서버는 `127.0.0.1` 에만 뜬다.

```sh
node session-fixation.mjs
```

```
$ node session-fixation.mjs
Node.js v24.15.0
세션 서버: http://127.0.0.1:49749

=== 취약: /vuln/login ===
1. 공격자가 고정 세션 ID 를 정한다: sid=ATTACKER-FIXED-SID
2. 피해자가 그 세션 ID 를 쿠키로 들고 로그인한다
   로그인 응답: 200, 발급된 sid: ATTACKER-FIXED-SID
   들어온 ID 와 같은가: true
3. 공격자가 쥔 ATTACKER-FIXED-SID 로 /me 를 요청한다
   -> 200 {"user":"victim"}  (가로채기 성공)

=== 고침: /safe/login ===
1. 공격자가 고정 세션 ID 를 정한다: sid=ATTACKER-FIXED-SID
2. 피해자가 그 세션 ID 를 쿠키로 들고 로그인한다
   로그인 응답: 200, 발급된 sid: 4e33abdd-73a7-474e-9b01-7a366c10aa8f
   들어온 ID 와 같은가: false
3. 공격자가 쥔 ATTACKER-FIXED-SID 로 /me 를 요청한다
   -> 401 {"error":"unauthorized"}  (가로채기 실패)

--- 요약 ---
취약: 발급 sid=ATTACKER-FIXED-SID (고정 ID 그대로), 공격자 /me -> 200
고침: 발급 sid=4e33abdd-73a7-474e-9b01-7a366c10aa8f (새 ID, 고정 ID와 다름), 공격자 /me -> 401
```

포트 번호는 실행마다 달라진다. 고친 쪽이 발급하는 새 세션 ID 는 `randomUUID()` 라 매 실행 바뀐다. 위 출력의 `4e33abdd-...` 는 그 한 번의 실행에서 나온 값이다. 바뀌지 않는 것은 공격자가 정한 고정 ID(`ATTACKER-FIXED-SID`)와, 취약/고침의 `/me` 상태 코드(200 대 401)다.

## 읽는 법

- 취약한 쪽은 로그인 뒤에도 발급된 sid 가 `ATTACKER-FIXED-SID` 그대로다(`들어온 ID 와 같은가: true`). 그래서 같은 ID 를 쥔 공격자의 `/me` 가 200 에 `{"user":"victim"}` 을 돌려준다. 공격자가 피해자의 로그인 세션을 그대로 쓴다.
- 고친 쪽은 로그인 때 `randomUUID()` 로 새 ID 를 발급하고 옛 세션(`ATTACKER-FIXED-SID`)을 `sessions.delete` 로 버린다. 피해자는 새 ID 로만 로그인되어 있다. 공격자가 쥔 `ATTACKER-FIXED-SID` 는 저장소에 없어 `/me` 가 401 이다.

## 한계

- **쿠키 전달은 클라이언트가 직접 `Cookie` 헤더를 붙여 흉내 낸다.** 브라우저의 쿠키 저장소나 `Set-Cookie` 자동 반영을 쓰지 않는다. 공격자가 어떻게 피해자에게 세션 ID 를 심는지(쿼리 파라미터·`Set-Cookie`·XSS 등 실제 주입 경로)는 재현하지 않는다. 이미 피해자가 고정 ID 를 들고 로그인한다는 전제에서 돈다.
- **측정하는 것은 서버의 세션 저장소 동작과 응답뿐이다.** 실제 브라우저가 `Set-Cookie` 로 바뀐 세션 ID 를 어떻게 쓰는지, 공격자 브라우저에서 `/me` 가 어떻게 보이는지는 측정하지 않는다.
- 세션 ID 의 무작위성·엔트로피, `Secure`/`SameSite` 속성, 세션 만료, 로그아웃 시 폐기 같은 세션 관리의 다른 측면은 다루지 않는다. 보이는 것은 "로그인 시 재발급" 하나다.
- 취약한 쪽에서 들어온 sid 가 비어 있으면(`undefined`) 그 값으로도 세션이 만들어진다. 실제 서버라면 들어온 ID 를 그대로 신뢰하는 것 자체가 문제의 뿌리다. 이 PoC 는 공격자가 ID 를 정해 보내는 경우만 보인다.

## 파일

- `session-fixation.mjs`: 세션 저장소, 두 로그인 경로, 보호된 `/me`, 공격 시나리오 데모를 한 파일에 담았다.
