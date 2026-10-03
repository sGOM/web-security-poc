# JWT 서명 검증 (JWT Signature Verification)

JWT는 받은 사람 누구나 payload를 읽을 수 있고, 무결성 보장은 받는 쪽이 서명을 제대로 검증했을 때만 성립한다. 서명을 검증하지 않거나 헤더의 `alg`를 믿으면 토큰이 위조된다. 방어는 세 가지를 순서대로 한다. 서버가 `alg`를 고정하고(헤더를 믿지 않는다), 그 알고리즘과 서버 키로 서명을 검증하고, `exp`를 본다([RFC 8725](https://www.rfc-editor.org/rfc/rfc8725)).

글: [JWT: 서명, 만료, 저장 위치](https://sgom.github.io/posts/jwt-basics/)

## 무엇을 보이나

블로그 글의 `jwt_demo.py`와 같은 키(32바이트)·클레임·토큰을 쓴다. Python 3 표준 라이브러리(`hmac`, `hashlib`, `base64`, `json`)만 쓰고 서버도 네트워크도 없다. HS256 토큰 하나를 발급하고, 공격 토큰 두 개를 만들어 취약 검증기와 고친 검증기에 같은 토큰을 넣어 결과(통과/거부)를 대조한다. `now`는 재현되도록 고정값(`1788000600`, `1788000900`)을 넘긴다.

두 검증기를 나란히 둔다.

- `verify_vuln` (취약): payload를 base64url로 풀어 그대로 믿는다. `alg`를 고정하지 않고 서명도 `exp`도 보지 않는다.
- `verify_safe` (고침): `alg`를 `HS256`으로 고정하고(헤더를 믿지 않는다) → 서명을 검증하고 → `exp`를 본다. 글의 `verify`와 같은 동작이다.

공격 토큰 두 개.

- **payload 변조**: 원본 HS256 토큰의 payload에서 `role`을 `user`에서 `admin`으로 바꾸고 옛 서명 조각을 그대로 둔다. 서명 대상 문자열이 바뀌어 HMAC이 맞지 않는다.
- **alg=none**: 헤더를 `{"alg":"none","typ":"JWT"}`로 바꾸고, payload는 `role=admin`으로, 서명 조각은 비운다([RFC 7518 3.6절](https://www.rfc-editor.org/rfc/rfc7518#section-3.6)).

## 취약: 서명 미검증 / alg 미고정

```python
def verify_vuln(token: str, key: bytes, now: int) -> dict:
    # 취약: alg를 고정하지 않고, 서명도 exp도 검증하지 않는다. payload를 디코딩해 그대로 믿는다.
    h, p, s = token.split(".")
    return json.loads(b64url_decode(p))
```

## 고침: alg 고정 + 서명 검증 + exp

```python
def verify_safe(token: str, key: bytes, now: int) -> dict:
    # 고침: alg 고정 → 서명 검증 → exp 검사 (RFC 7519 7.2, RFC 8725 3.1)
    h, p, s = token.split(".")
    alg = json.loads(b64url_decode(h)).get("alg")
    if alg != "HS256":                                    # 헤더가 아니라 서버가 alg를 정한다
        raise ValueError(f"허용하지 않는 alg: {alg}")
    expected = hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, b64url_decode(s)):
        raise ValueError("서명 불일치")
    claims = json.loads(b64url_decode(p))
    if now >= claims["exp"]:
        raise ValueError("만료")
    return claims
```

`alg`를 먼저 고정하므로 `none`은 서명을 계산하기도 전에 거부된다. 서명은 서버 키로 다시 계산한 HMAC과 `hmac.compare_digest`(상수 시간 비교)로 맞춰 본다. `exp`는 그 시각을 포함해 거부한다(`now >= exp`, [RFC 7519 4.1.4절](https://www.rfc-editor.org/rfc/rfc7519#section-4.1.4)).

## 실행

Python 3(표준 라이브러리만, 확인한 버전 3.14.4). 의존성 없음. 네트워크를 쓰지 않는다. 한글 출력이 깨지는 콘솔에서는 `-X utf8`을 붙인다.

```sh
python -X utf8 jwt_demo.py
```

## 실제 출력

아래는 `jwt_demo.py`를 실행한 출력이다. 입력이 전부 고정값이라 실행마다 같다(두 번 실행해 동일함을 확인했다).

```
=== 1. 발급 (HS256) ===
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsInJvbGUiOiJ1c2VyIiwiaWF0IjoxNzg4MDAwMDAwLCJleHAiOjE3ODgwMDA5MDB9.QGrHgwA7SjsoQOoSh8eN5pjS_NNIci7QrSfWj58H6pk

=== 2. 공격 토큰 ===
payload 변조(role=admin, 옛 서명): eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiI0MiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc4ODAwMDAwMCwiZXhwIjoxNzg4MDAwOTAwfQ.QGrHgwA7SjsoQOoSh8eN5pjS_NNIci7QrSfWj58H6pk
alg=none(role=admin, 서명 없음)  : eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiI0MiIsInJvbGUiOiJhZG1pbiIsImlhdCI6MTc4ODAwMDAwMCwiZXhwIjoxNzg4MDAwOTAwfQ.

=== 3. 취약/고침 대조 (now=1788000600, exp=1788000900) ===
[A] 원본 토큰
  취약 verify_vuln   -> 통과 {'sub': '42', 'role': 'user', 'iat': 1788000000, 'exp': 1788000900}
  고침 verify_safe   -> 통과 {'sub': '42', 'role': 'user', 'iat': 1788000000, 'exp': 1788000900}
[B] payload 변조 (role=admin, HS256, 옛 서명)
  취약 verify_vuln   -> 통과 {'sub': '42', 'role': 'admin', 'iat': 1788000000, 'exp': 1788000900}
  고침 verify_safe   -> 거부 (서명 불일치)
[C] alg=none (role=admin, 서명 없음)
  취약 verify_vuln   -> 통과 {'sub': '42', 'role': 'admin', 'iat': 1788000000, 'exp': 1788000900}
  고침 verify_safe   -> 거부 (허용하지 않는 alg: none)
[D] 원본 토큰, 발급 15분 뒤 (now=1788000900, 만료)
  취약 verify_vuln   -> 통과 {'sub': '42', 'role': 'user', 'iat': 1788000000, 'exp': 1788000900}
  고침 verify_safe   -> 거부 (만료)
```

## 읽는 법

- **[B] payload 변조**: `role`을 `admin`으로 바꾸면 HMAC 대상 문자열이 바뀌어 옛 서명이 맞지 않는다. 서명을 보는 `verify_safe`는 `서명 불일치`로 거부하고, 서명을 안 보는 `verify_vuln`은 `role=admin`을 통과시킨다. 키가 없는 공격자는 맞는 HS256 서명을 새로 만들 수 없다.
- **[C] alg=none**: `verify_safe`는 `alg`를 `HS256`으로 고정해 서명을 계산하기 전에 거부한다. `verify_vuln`은 `alg`를 보지 않으므로 서명 없는 `role=admin` 토큰을 통과시킨다. [RFC 8725 2.1절](https://www.rfc-editor.org/rfc/rfc8725#section-2.1)이 실제 있었던 공격으로 적은 형태다.
- **[D] 만료**: `exp`를 보는 `verify_safe`는 `만료`로 거부하고, `exp`를 안 보는 `verify_vuln`은 통과시킨다.

## 글(jwt-basics)과의 관계

글의 `jwt_demo.py`는 취약 검증기로 `naive_verify`를 쓴다. `naive_verify`는 헤더의 `alg`를 믿되(`none`이면 통과) HS256 서명은 `verify`로 검증하므로, payload만 바꾼 HS256 토큰([B])은 거부한다. 이 PoC의 `verify_vuln`은 한 걸음 더 나아가 서명을 아예 보지 않는 흔한 실수를 모델링해, [B]의 payload 변조까지 통과하는 것을 보인다. 고친 쪽(`verify_safe`)은 글의 `verify`와 같은 동작·같은 거부 사유다. 발급 토큰·`none` 토큰 문자열, 거부 사유 문자열(`서명 불일치`·`만료`·`허용하지 않는 alg: none`)은 글과 일치한다.

## 한계

- **이 PoC는 검증 로직의 취약점만 보인다.** 특정 라이브러리의 CVE, 키 탈취, 약한 키의 오프라인 대입(brute-force)은 다루지 않는다.
- **RS256→HS256 키 혼동(key confusion) 공격은 재현하지 않는다.** 글이 언급만 하는 이 공격(공개 키를 HMAC 비밀 키로 쓰게 만드는 것)은 여기 코드에 없다. 막는 방법은 `alg` 고정으로 같다.
- **검증 순서의 1~2단계(`alg`, 서명)와 3단계의 `exp`만 본다.** `nbf`, `iss`, `aud`(글 표의 3~4단계)는 검사하지 않는다.
- **`verify_vuln`은 글의 `naive_verify`보다 더 허술한 검증기다.** 둘 다 "취약"이지만 같은 함수는 아니다(위 「글과의 관계」 참고).

## 파일

- `jwt_demo.py`: 키·클레임·토큰, 두 검증기(`verify_vuln`/`verify_safe`), 공격 토큰 두 개, 대조 출력을 한 파일에 담았다.
