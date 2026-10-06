# jwt_demo.py가 만든 토큰을 PyJWT로 검증한다. pip install pyjwt
import sys
import jwt

KEY = bytes.fromhex("8f2c1e9a4b7d3f60a5c2e8b1d4f7a3c6e9b2d5f8a1c4e7b0d3f6a9c2e5b8d1f4")
token, none_token = sys.argv[1], sys.argv[2]

print("PyJWT", jwt.__version__)
for label, t, kwargs in [
    ("원본, algorithms=['HS256']", token, {"algorithms": ["HS256"]}),
    ("alg none, algorithms=['HS256']", none_token, {"algorithms": ["HS256"]}),
    ("원본, algorithms 생략", token, {}),
]:
    try:
        claims = jwt.decode(t, KEY, options={"verify_exp": False}, **kwargs)
        print(f"{label}\n  -> 통과 {claims}")
    except jwt.PyJWTError as e:
        print(f"{label}\n  -> 거부 {type(e).__name__}: {e}")
