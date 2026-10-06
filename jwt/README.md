# JWT — 서명 검증과 alg 혼동

JWT(JWS)를 표준 라이브러리만으로 만들고 검증해, **서명이 막는 것과 막지 못하는 것, 검증 순서**를 보인다. `HS256` 토큰을 발급하고 세 가지를 검증기에 넣는다. 원본, `role`만 `admin`으로 바꾼 토큰, `alg`를 `none`으로 바꿔 서명을 비운 토큰이다.

글: [JWT: 서명, 만료, 저장 위치](https://sgom.github.io/posts/jwt-basics/)

## 파일

| 파일 | 하는 일 | 실행 |
|---|---|---|
| `jwt_demo.py` | HS256 발급, 키 없이 읽기, 엄격한 검증기(`verify`)와 헤더의 alg를 믿는 검증기(`naive_verify`)의 대조 | `python -X utf8 jwt_demo.py` |
| `verify.mjs` | 같은 토큰을 Node.js 표준 `crypto`로 재검증(형식 교차 확인) | `node verify.mjs "<token>"` |
| `with_pyjwt.py` | 같은 토큰을 PyJWT로 검증(`algorithms` 허용 목록 강제) | `pip install pyjwt` 뒤 `python -X utf8 with_pyjwt.py "<token>" "<none_token>"` |

## 무엇을 보이나

- **서명은 내용을 숨기지 않는다.** header·payload는 base64url이라 키 없이 읽힌다.
- **변조는 서명으로 걸린다.** `role`만 `admin`으로 바꾸고 서명을 그대로 두면, 서명 대상 문자열이 달라져 `verify`가 거부한다.
- **`exp`는 서명 검증 뒤에 본다.** 발급 15분 뒤(= `exp`와 같은 순간)에는 거부된다.
- **alg=none 공격.** 헤더의 `alg`를 믿는 `naive_verify`는 서명을 보지 않고 `role: admin`을 통과시킨다. 알고리즘을 `HS256`으로 고정하는 `verify`는 거부한다([RFC 8725 2.1·3.1](https://www.rfc-editor.org/rfc/rfc8725)). PyJWT는 `algorithms`를 넘기지 않으면 검증을 시작하지 않고, 허용 목록에 없는 `none`을 거부한다.

## 실행 출력

`jwt_demo.py`는 시각을 고정값으로 넘겨 출력이 재현된다(토큰 문자열까지 매번 같다). 확인 버전 Python 3.14.4.

```
=== 1. 발급 ===
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzg4MDAwMDAwLCJleHAiOjE3ODgwMDA5MDB9.QGrHgwA7SjsoQOoSh8eN5pjS_NNIci7QrSfWj58H6pk

=== 2. 키 없이 읽기 ===
header   {"alg":"HS256","typ":"JWT"}
payload  {"sub":"42","role":"user","iat":1788000000,"exp":1788000900}
exp      2026-08-29 10:55:00+00:00

=== 3. 검증 ===
none 토큰: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiI0MiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc4ODAwMDAwMCwiZXhwIjoxNzg4MDAwOTAwfQ.
원본, 발급 10분 뒤
  -> 통과 {'sub': '42', 'role': 'user', 'iat': 1788000000, 'exp': 1788000900}
role만 admin으로 바꿈
  -> 거부 (서명 불일치)
원본, 발급 15분 뒤
  -> 거부 (만료)
alg none, 엄격한 검증기
  -> 거부 (허용하지 않는 alg: none)
alg none, 헤더를 믿는 검증기
  -> 통과 {'sub': '42', 'role': 'admin', 'iat': 1788000000, 'exp': 1788000900}
```

`verify.mjs`와 `with_pyjwt.py`는 그 발급 토큰을 받아 각각 Node `crypto`와 PyJWT로 다시 검증한다. PyJWT 버전 문자열은 설치본에 따라 다르다(확인 2.15.1).

```
서명 일치: true
payload: { sub: '42', role: 'user', iat: 1788000000, exp: 1788000900 }
```

```
PyJWT 2.15.1
원본, algorithms=['HS256']
  -> 통과 {'sub': '42', 'role': 'user', 'iat': 1788000000, 'exp': 1788000900}
alg none, algorithms=['HS256']
  -> 거부 InvalidAlgorithmError: The specified alg value is not allowed
원본, algorithms 생략
  -> 거부 DecodeError: It is required that you pass in a value for the "algorithms" argument when calling decode().
```

## 한계

- 검증 로직의 취약점만 보인다. 라이브러리 CVE, 키 탈취, 약한 키의 오프라인 대입은 다루지 않는다.
- `RS256`→`HS256` 키 혼동 공격은 재현하지 않는다(글이 설명으로 다룸). 막는 방법은 같다 — `alg`를 서버가 고정한다.
- 검증 순서 1~2단계(`alg`, 서명)와 `exp`만 본다. `nbf`·`iss`·`aud`는 검사하지 않는다.
- HMAC 비교에 `hmac.compare_digest`(상수 시간)를 쓴다. 그 원리는 `timing-attack/` PoC에 있다.
