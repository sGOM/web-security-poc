# JWT 서명 검증의 취약점을 Python 표준 라이브러리만으로 보인다. 외부 라이브러리·네트워크 없음.
# 취약 verify_vuln(서명 미검증·alg 미고정)과 고침 verify_safe(alg 고정+서명+exp)를 나란히 두고,
# 같은 공격 토큰을 둘에 넣어 결과(통과/거부)를 대조한다. 시각은 재현되도록 고정값을 넘긴다.
import base64, hashlib, hmac, json

KEY = bytes.fromhex("8f2c1e9a4b7d3f60a5c2e8b1d4f7a3c6e9b2d5f8a1c4e7b0d3f6a9c2e5b8d1f4")  # 32바이트


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def part(obj: dict) -> str:
    return b64url(json.dumps(obj, separators=(",", ":")).encode())


def sign(header: dict, claims: dict, key: bytes) -> str:
    signing_input = part(header) + "." + part(claims)
    sig = hmac.new(key, signing_input.encode(), hashlib.sha256).digest()
    return signing_input + "." + b64url(sig)


def verify_vuln(token: str, key: bytes, now: int) -> dict:
    # 취약: alg를 고정하지 않고, 서명도 exp도 검증하지 않는다. payload를 디코딩해 그대로 믿는다.
    h, p, s = token.split(".")
    return json.loads(b64url_decode(p))


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


def attempt(token: str, now: int) -> None:
    for label, fn in (("취약 verify_vuln", verify_vuln), ("고침 verify_safe", verify_safe)):
        try:
            result = f"통과 {fn(token, KEY, now)}"
        except ValueError as e:
            result = f"거부 ({e})"
        print(f"  {label:16} -> {result}")


header = {"alg": "HS256", "typ": "JWT"}
claims = {"sub": "42", "role": "user", "iat": 1788000000, "exp": 1788000900}   # 15분짜리
token = sign(header, claims, KEY)
h, p, s = token.split(".")

# 공격 토큰 두 개
forged = h + "." + part({**claims, "role": "admin"}) + "." + s                 # HS256 헤더, payload만 변조, 옛 서명 유지
none_token = part({"alg": "none", "typ": "JWT"}) + "." + part({**claims, "role": "admin"}) + "."  # alg=none, 서명 비움

print("=== 1. 발급 (HS256) ===")
print(token)
print()
print("=== 2. 공격 토큰 ===")
print("payload 변조(role=admin, 옛 서명):", forged)
print("alg=none(role=admin, 서명 없음)  :", none_token)
print()
print("=== 3. 취약/고침 대조 (now=1788000600, exp=1788000900) ===")
print("[A] 원본 토큰")
attempt(token, 1788000600)
print("[B] payload 변조 (role=admin, HS256, 옛 서명)")
attempt(forged, 1788000600)
print("[C] alg=none (role=admin, 서명 없음)")
attempt(none_token, 1788000600)
print("[D] 원본 토큰, 발급 15분 뒤 (now=1788000900, 만료)")
attempt(token, 1788000900)
