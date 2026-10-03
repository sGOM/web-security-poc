# JWT 서명 검증 (JWT Signature Verification)

JWT는 받은 사람 누구나 payload를 읽을 수 있고, 무결성 보장은 받는 쪽이 서명을 제대로 검증했을 때만 성립한다. 서명을 검증하지 않거나 헤더의 `alg`를 믿으면 토큰이 위조된다. 방어는 세 가지를 순서대로 한다. 서버가 `alg`를 고정하고(헤더를 믿지 않는다), 그 알고리즘과 서버 키로 서명을 검증하고, `exp`를 본다([RFC 8725](https://www.rfc-editor.org/rfc/rfc8725)).

글: [JWT: 서명, 만료, 저장 위치](https://sgom.github.io/posts/jwt-basics/)

## 무엇을 보이나

블로그 글과 같은 키(32바이트)·클레임·토큰을 쓴다. HS256 토큰 하나를 발급하고, 공격 토큰 두 개를 만들어 세 검증기에 같은 토큰을 넣어 결과(통과/거부)를 대조한다. `node:crypto`의 HMAC-SHA256과 base64url만 쓴다. 서버도 네트워크도 없다. `now`는 재현되도록 고정값(`1788000600`, `1788000900`)을 넘긴다.

세 검증기를 나란히 둔다.

- `verifyNoSig` (취약: 서명 미검증): payload를 base64url로 풀어 그대로 믿는다. 서명도 `exp`도 보지 않는다.
- `verifyAlgTrust` (취약: alg 미고정): 헤더의 `alg`를 믿는다. `none`이면 서명을 안 보고 통과시키고, `HS256`이면 서명을 검증한다. [RFC 8725 2.1절](https://www.rfc-editor.org/rfc/rfc8725#section-2.1)이 경고하는 형태다.
- `verifySafe` (고침): `alg`를 `HS256`으로 고정하고(헤더를 믿지 않는다) → 서명을 검증하고 → `exp`를 본다.

공격 토큰 두 개.

- **payload 변조**: 원본 HS256 토큰의 payload에서 `role`을 `user`에서 `admin`으로 바꾸고 옛 서명 조각을 그대로 둔다. 서명 대상 문자열이 바뀌어 HMAC이 맞지 않는다.
- **alg=none**: 헤더를 `{"alg":"none","typ":"JWT"}`로 바꾸고, payload는 `role=admin`으로, 서명 조각은 비운다([RFC 7518 3.6절](https://www.rfc-editor.org/rfc/rfc7518#section-3.6)).

## 취약: 서명 미검증 / alg 미고정

```js
// 취약 1: 서명을 검증하지 않는다. payload를 디코딩해 그대로 믿는다. exp도 안 본다.
function verifyNoSig(token) {
  const [, p] = token.split(".");
  return decodeJson(p);
}

// 취약 2: 헤더의 alg를 믿는다. RFC 8725 2.1이 경고하는 형태다.
function verifyAlgTrust(token, key, now) {
  const [h, p] = token.split(".");
  const alg = decodeJson(h).alg;
  if (alg === "none") {
    return decodeJson(p); // 서명을 보지 않고 통과시킨다
  }
  return verifySafe(token, key, now);
}
```

## 고침: alg 고정 + 서명 검증 + exp

```js
// 고침: alg 고정 → 서명 검증 → exp 검사 (RFC 7519 7.2, RFC 8725 3.1)
function verifySafe(token, key, now) {
  const [h, p, s] = token.split(".");
  const alg = decodeJson(h).alg;
  if (alg !== "HS256") {
    throw new Error(`허용하지 않는 alg: ${alg}`); // 헤더가 아니라 서버가 alg를 정한다
  }
  const expected = crypto.createHmac("sha256", key).update(`${h}.${p}`).digest();
  const actual = Buffer.from(s ?? "", "base64url");
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    throw new Error("서명 불일치");
  }
  const claims = decodeJson(p);
  if (now >= claims.exp) {
    throw new Error("만료");
  }
  return claims;
}
```

`alg`를 먼저 고정하므로 `none`은 서명을 계산하기도 전에 거부된다. 서명은 서버 키로 다시 계산한 HMAC과 [`crypto.timingSafeEqual`](https://nodejs.org/docs/latest-v24.x/api/crypto.html#cryptotimingsafeequala-b)로 비교한다(길이가 다르면 예외를 던지므로 길이를 먼저 본다). `exp`는 그 시각을 포함해 거부한다(`now >= exp`, [RFC 7519 4.1.4절](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4)).

## 실행

Node.js 24. 의존성 없음. 네트워크를 쓰지 않는다.

```sh
node jwt.mjs
```

## 실제 출력

아래는 `jwt.mjs`를 실행한 출력이다. `process.version`을 빼면 실행마다 같다(두 번 실행해 동일함을 확인했다).

```
v24.15.0
=== 1. 발급 (HS256) ===
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzg4MDAwMDAwLCJleHAiOjE3ODgwMDA5MDB9.QGrHgwA7SjsoQOoSh8eN5pjS_NNIci7QrSfWj58H6pk

=== 2. 공격 토큰 ===
payload 변조(role=admin, 옛 서명): eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc4ODAwMDAwMCwiZXhwIjoxNzg4MDAwOTAwfQ.QGrHgwA7SjsoQOoSh8eN5pjS_NNIci7QrSfWj58H6pk
alg=none(role=admin, 서명 없음)  : eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiI0MiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc4ODAwMDAwMCwiZXhwIjoxNzg4MDAwOTAwfQ.

=== 3. 세 검증기 대조 (now=1788000600, exp=1788000900) ===
[A] 원본 토큰
  취약: 서명 미검증             -> 통과 {"sub":"42","role":"user","iat":1788000000,"exp":1788000900}
  취약: alg 미고정            -> 통과 {"sub":"42","role":"user","iat":1788000000,"exp":1788000900}
  고침: verifySafe         -> 통과 {"sub":"42","role":"user","iat":1788000000,"exp":1788000900}
[B] payload 변조 (role=admin, HS256, 옛 서명)
  취약: 서명 미검증             -> 통과 {"sub":"42","role":"admin","iat":1788000000,"exp":1788000900}
  취약: alg 미고정            -> 거부 (서명 불일치)
  고침: verifySafe         -> 거부 (서명 불일치)
[C] alg=none (role=admin, 서명 없음)
  취약: 서명 미검증             -> 통과 {"sub":"42","role":"admin","iat":1788000000,"exp":1788000900}
  취약: alg 미고정            -> 통과 {"sub":"42","role":"admin","iat":1788000000,"exp":1788000900}
  고침: verifySafe         -> 거부 (허용하지 않는 alg: none)
[D] 원본 토큰, 발급 15분 뒤 (now=1788000900, 만료)
  취약: 서명 미검증             -> 통과 {"sub":"42","role":"user","iat":1788000000,"exp":1788000900}
  취약: alg 미고정            -> 거부 (만료)
  고침: verifySafe         -> 거부 (만료)
```

## 읽는 법

- **[B] payload 변조**: `role`을 `admin`으로 바꾸면 HMAC 대상 문자열이 바뀌어 옛 서명이 맞지 않는다. 서명을 보는 `verifyAlgTrust`와 `verifySafe`는 `서명 불일치`로 거부하고, 서명을 안 보는 `verifyNoSig`는 `role=admin`을 통과시킨다. 키가 없는 공격자는 맞는 HS256 서명을 새로 만들 수 없다.
- **[C] alg=none**: `verifySafe`만 거부한다. 이 행이 "헤더의 `alg`를 믿는 것"이 바로 그 취약점임을 보인다. `verifyAlgTrust`는 HS256 서명은 제대로 검증하는데도(그래서 [B]는 거부했다) `alg=none` 앞에서는 서명을 보지 않고 통과시킨다. `verifySafe`는 `alg`를 `HS256`으로 고정해 서명을 계산하기 전에 거부한다.
- **[D] 만료**: `exp`를 보는 두 검증기는 `만료`로 거부하고, `exp`를 안 보는 `verifyNoSig`는 통과시킨다.

## 한계

- **이 PoC는 검증 로직의 취약점만 보인다.** 특정 라이브러리의 CVE, 키 탈취, 약한 키의 오프라인 대입(brute-force)은 다루지 않는다.
- **RS256→HS256 키 혼동(key confusion) 공격은 재현하지 않는다.** 글이 언급만 하는 이 공격(공개 키를 HMAC 비밀 키로 쓰게 만드는 것)은 여기 코드에 없다. 막는 방법은 `alg` 고정으로 같다.
- **검증 순서의 1~2단계(`alg`, 서명)와 3단계의 `exp`만 본다.** `nbf`, `iss`, `aud`(글 표의 3~4단계)는 검사하지 않는다.
- **출력 포맷이 블로그의 Python 데모와 다르다.** Node는 claim을 `{"sub":"42",...}`(JSON)로 찍고, 블로그의 `jwt_demo.py`는 Python dict `{'sub': '42', ...}`로 찍는다. 발급 토큰·`none` 토큰 문자열과 거부 사유(`서명 불일치`·`만료`·`허용하지 않는 alg: none`)는 양쪽이 같다.

## 파일

- `jwt.mjs`: 키·클레임·토큰, 세 검증기(`verifyNoSig`/`verifyAlgTrust`/`verifySafe`), 공격 토큰 두 개, 대조 출력을 한 파일에 담았다.
