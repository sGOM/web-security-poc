# HS256 JWT를 표준 라이브러리만으로 만들고 검증한다.
import base64, hashlib, hmac, json
from datetime import datetime, UTC

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

def verify(token: str, key: bytes, now: int) -> dict:
    h, p, s = token.split(".")
    alg = json.loads(b64url_decode(h)).get("alg")
    if alg != "HS256":                                    # 헤더의 alg를 믿지 않고 고정한다
        raise ValueError(f"허용하지 않는 alg: {alg}")
    expected = hmac.new(key, f"{h}.{p}".encode(), hashlib.sha256).digest()
    if not hmac.compare_digest(expected, b64url_decode(s)):
        raise ValueError("서명 불일치")
    claims = json.loads(b64url_decode(p))
    if now >= claims["exp"]:
        raise ValueError("만료")
    return claims

def naive_verify(token: str, key: bytes, now: int) -> dict:
    # 헤더의 alg를 그대로 따르는 검증기. RFC 8725 2.1이 경고하는 형태다.
    h, p, s = token.split(".")
    if json.loads(b64url_decode(h)).get("alg") == "none":
        return json.loads(b64url_decode(p))
    return verify(token, key, now)

def attempt(label, fn, token, now):
    try:
        result = f"통과 {fn(token, KEY, now)}"
    except ValueError as e:
        result = f"거부 ({e})"
    print(label)
    print(f"  -> {result}")

header = {"alg": "HS256", "typ": "JWT"}
claims = {"sub": "42", "role": "user", "iat": 1788000000, "exp": 1788000900}   # 15분짜리
token = sign(header, claims, KEY)

print("=== 1. 발급 ===")
print(token)
print()
print("=== 2. 키 없이 읽기 ===")
for name, seg in zip(("header", "payload"), token.split(".")[:2]):
    print(f"{name:8} {b64url_decode(seg).decode()}")
print(f"exp      {datetime.fromtimestamp(claims['exp'], UTC)}")
print()
print("=== 3. 검증 ===")
h, p, s = token.split(".")
forged = h + "." + part({**claims, "role": "admin"}) + "." + s
none_token = part({"alg": "none", "typ": "JWT"}) + "." + part({**claims, "role": "admin"}) + "."
print("none 토큰:", none_token)
attempt("원본, 발급 10분 뒤", verify, token, 1788000600)
attempt("role만 admin으로 바꿈", verify, forged, 1788000600)
attempt("원본, 발급 15분 뒤", verify, token, 1788000900)
attempt("alg none, 엄격한 검증기", verify, none_token, 1788000600)
attempt("alg none, 헤더를 믿는 검증기", naive_verify, none_token, 1788000600)
