import hashlib
import hmac
import time

PEPPER = b"pepper-from-env"


def digest(password, salt=b"", pepper=b""):
    if pepper:
        password = hmac.new(pepper, password, hashlib.sha256).digest()
    return hashlib.scrypt(password, salt=salt, n=2**14, r=8, p=1, dklen=32).hex()


users = [("alice", b"hunter2"), ("bob", b"hunter2"), ("carol", b"correct horse")]

for label, use_salt, pepper in [
    ("no salt", False, b""),
    ("per-user salt", True, b""),
    ("salt + pepper", True, PEPPER),
]:
    print("--", label)
    for name, pw in users:
        salt = name.encode() if use_salt else b""
        print(" ", name, digest(pw, salt=salt, pepper=pepper)[:32])

print("-- attacker has the database but not the pepper")
print("  guess ", digest(b"hunter2", salt=b"alice")[:32])
print("  stored", digest(b"hunter2", salt=b"alice", pepper=PEPPER)[:32])

start = time.perf_counter()
for _ in range(10):
    digest(b"x", salt=b"y")
per_call = (time.perf_counter() - start) / 10

print("-- 100 candidates against 1000 accounts")
print("  scrypt(n=2**14, r=8, p=1): %.0f ms per call" % (per_call * 1000))
print("  no salt:       %6d calls, %8.1f s" % (100, 100 * per_call))
print("  per-user salt: %6d calls, %8.1f s" % (100000, 100000 * per_call))
