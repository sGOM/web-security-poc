import bcrypt

stored = bcrypt.hashpw(b"hunter2", bcrypt.gensalt(12)).decode()
print(stored)
print("prefix ", stored[:7])
print("salt   ", stored[7:29], len(stored[7:29]))
print("digest ", stored[29:], len(stored[29:]))
print("verify ", bcrypt.checkpw(b"hunter2", stored.encode()),
      bcrypt.checkpw(b"wrong", stored.encode()))
