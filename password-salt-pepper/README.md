# 비밀번호 해시의 salt와 pepper (Password Salt & Pepper)

같은 비밀번호가 같은 해시로 저장될 때 무엇이 무너지는지, salt와 pepper가 각각 어느 쪽을 막는지 Python 3 표준 라이브러리로 보인다. salt 없는 쪽과 넣은 쪽, pepper까지 넣은 쪽을 한 실행에서 나란히 찍어 대비한다.

글: [비밀번호 해시의 salt와 pepper — 각각 무엇을 막는가](https://sgom.github.io/posts/password-salt-and-pepper/)

## 무엇을 보이나

블로그 글의 `saltpepper.py`와 같은 코드·같은 값을 쓴다. `hashlib.scrypt`([RFC 7914](https://datatracker.ietf.org/doc/html/rfc7914))로 느린 해시를 돌리고 `hmac`으로 pepper를 적용한다. 서버도 네트워크도 없다. 출력을 고정하려고 salt는 사용자 이름을, pepper는 소스에 박은 상수(`b"pepper-from-env"`)를 쓴다. 실제로는 salt를 `secrets.token_bytes(16)`으로 만들어 해시와 함께 저장하고 pepper는 환경 변수나 키 관리 서비스에서 읽는다.

세 경우를 세 블록으로 나란히 둔다.

- **no salt** — salt를 붙이지 않는다. 같은 비밀번호(`hunter2`)를 쓰는 alice와 bob의 다이제스트가 글자까지 같다(`b802d1f4…`). DB만 봐도 둘이 같은 비밀번호라는 사실이 드러나고, 한 번 깬 결과를 그 무리 전체에 재사용할 수 있다.
- **per-user salt** — salt를 비밀번호마다 다르게 붙인다. 같은 `hunter2`인데도 alice(`1555472e…`)와 bob(`438d20a6…`)이 갈린다. 같은 값으로 묶이는 일이 사라진다.
- **salt + pepper** — salt에 더해 서버만 가진 pepper로 비밀번호를 HMAC 변환한 뒤 해시한다.

그다음 두 블록으로 pepper의 몫과 salt의 몫을 각각 보인다.

- **attacker has the database but not the pepper** — DB를 통째로 가져가 salt까지 알고 정답 `hunter2`를 넣어 계산한 `guess`(`1555472e…`, per-user salt 블록의 alice와 같다)가, DB에 실제로 저장된 `stored`(`55a1923d…`, salt + pepper 블록의 alice와 같다)와 다르다. pepper가 DB에 없으므로 DB만 가진 공격자는 맞는 후보를 넣고도 맞았다는 것을 확인하지 못한다.
- **100 candidates against 1000 accounts** — 후보 100개로 계정 1,000개를 터는 비용. salt가 없으면 후보당 한 번씩 100회로 끝난다. salt가 붙으면 계정마다 다시 계산해야 해서 호출이 정확히 1,000배(100,000회)로 는다. 뒤 두 줄의 초(秒)는 한 번 호출 시간(10회 평균)에 호출 횟수를 곱한 추정값이라 실행마다 달라진다.

## 실행

```
python -X utf8 saltpepper.py
```

Python 3 표준 라이브러리(`hashlib`, `hmac`, `time`)만 쓴다. 별도 설치가 없다.

## 실제 출력

Windows 11, Python 3.14.4에서 돌린 결과다. 다이제스트는 고정이고 마지막 세 줄(ms·초)만 환경과 실행마다 달라진다.

```
-- no salt
  alice b802d1f42592b08f61cb3781ec5bc49d
  bob b802d1f42592b08f61cb3781ec5bc49d
  carol 87d14174dd2a91abc09d7df4a279cf6a
-- per-user salt
  alice 1555472e42f139f7bcca0f901a0d708a
  bob 438d20a61b7076afadad93196387f13b
  carol a5d3f08f8d411c108837aeb0c2e7c04a
-- salt + pepper
  alice 55a1923d95a8655ca49a0ef848d4223f
  bob 65fa15f29879a5be8df39a7a9323f7da
  carol c7572cb5dbc94bf91845726b997bdcbf
-- attacker has the database but not the pepper
  guess  1555472e42f139f7bcca0f901a0d708a
  stored 55a1923d95a8655ca49a0ef848d4223f
-- 100 candidates against 1000 accounts
  scrypt(n=2**14, r=8, p=1): 58 ms per call
  no salt:          100 calls,      5.8 s
  per-user salt: 100000 calls,   5830.2 s
```

## 곁다리: bcrypt 문자열에 들어 있는 salt (`bcrypt_format.py`)

bcrypt가 뱉는 해시 문자열 안에 salt가 그대로 들어 있다는 것을 보이는 보조 데모다. 이 파일만 표준 라이브러리가 아니라 bcrypt가 필요하다.

```
pip install bcrypt        # 5.0.0으로 확인
python -X utf8 bcrypt_format.py
```

`gensalt`가 salt를 매번 새로 만들므로 22글자 salt와 31글자 다이제스트 자리의 문자는 **실행할 때마다 달라진다**. 아래는 한 번 돌린 결과이고, 재현 대상이 아니다. 고정되는 것은 구조뿐이다. 접두사 `$2b$12$`(알고리즘 `2b`, work factor `12`), salt 22글자, 다이제스트 31글자, 그리고 `verify  True False`.

```
$2b$12$PtPx5KBUKNxhAilt5Yds6OJyChy6/nNVfY2DtQgyZETor9VV0.oTC
prefix  $2b$12$
salt    PtPx5KBUKNxhAilt5Yds6O 22
digest  JyChy6/nNVfY2DtQgyZETor9VV0.oTC 31
verify  True False
```

## 한계

- 느린 해시·메모리 하드 함수의 파라미터 선택과 실제 공격 비용은 다루지 않고 salt·pepper의 역할 구분만 보인다. `n=2**14`는 실습용으로 낮춘 값이고, OWASP가 권하는 `N=2^17, r=8, p=1`은 `hashlib.scrypt`의 `maxmem` 기본값(32 MiB) 때문에 `maxmem`을 함께 올려야 돈다.
- `100 candidates against 1000 accounts`의 초(秒)는 실제로 100,000번을 돌려 잰 값이 아니라, 10회 평균 호출 시간에 호출 횟수를 곱한 추정값이다. 호출 횟수가 정확히 1,000배라는 것은 설계상 성립하고(계정마다 재계산), 총 시간 1,000배는 거기서 따라오는 추정이다.
- 미리 계산한 표(rainbow table)로 실제 역산을 수행하지는 않는다. 역산의 전제인 "같은 비밀번호 → 같은 다이제스트"가 성립함(no salt 블록)과, salt가 그 전제를 깨는 것, pepper가 DB만으로는 후보 검증을 막는 것까지만 보인다.
- 출력을 고정하려고 salt에 사용자 이름을, pepper에 소스 상수를 썼다. 실제 배포에서는 salt를 무작위로 생성해 저장하고 pepper는 DB 바깥에서 읽는다. 이 PoC는 역할 구분을 보일 뿐 운영 구성을 보이지 않는다.
- bcrypt 데모의 출력은 `gensalt`의 무작위성 때문에 실행마다 다르다. 재현되는 것은 문자열의 구조(접두사·길이·`verify` 결과)뿐이다.
