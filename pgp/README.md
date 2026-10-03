# PGP (GnuPG로 보는 공개키 암호화 · 서명 · 키 신뢰)

PGP가 세션 키와 공개 키를 섞어 메시지를 암호화하는 방식, 서명이 보장하는 범위, 그리고 "서명이 Good"인 것과 "그 키가 진짜 그 사람 것"인 것이 별개라는 점을 GnuPG(`gpg`)로 직접 해 본다. 빈 임시 키링을 만들어 Alice·Bob·사칭자 Mallory의 키를 그 자리에서 생성하고, 같은 흐름을 한 번에 실행한다.

글: [PGP: 공개 키로 메시지를 암호화하고 서명하는 방식](https://sgom.github.io/posts/pgp-basics/)

## 무엇을 보이나

스크립트 하나(`demo.sh`)가 다섯 단계를 순서대로 실행한다.

1. **키 생성** — Alice와 Bob의 키 쌍을 batch 모드로 만든다. 기본값은 서명·인증용 주 키(`ed25519 [SC]`)와 암호화용 서브키(`cv25519 [E]`)다.
2. **공개키 암호화 + 세션 키** — Alice가 Bob의 공개 키로 서명·암호화한다. `--list-packets`로 메시지 구조를 본다. 맨 앞 `pubkey enc packet`(tag 1)이 **Bob의 공개 키로 감싼 세션 키**이고, 그 세션 키로 암호화한 `aead encrypted packet`(tag 20) 안에 서명과 본문이 들어 있다. 공개키 연산은 세션 키 하나에만 쓰고 본문은 대칭 암호로 푼다.
3. **복호화 (개인 키를 가진 쪽만)** — Bob이 자기 개인 키로 세션 키를 풀어 본문을 읽고, Alice의 서명이 `Good`임을 본다. 이어 **Bob의 개인 키가 없는 제3자(Eve)** 의 키링에서 같은 파일을 열어 본다. Eve에게는 바깥의 두 패킷(tag 1, tag 20)만 보이고, 복호화는 `No secret key`로 실패한다(종료 코드 2).
4. **서명 검증과 변조 (Good → BAD)** — 평문 서명(`--clearsign`)을 만들어 그대로 검증하면 `Good signature`(종료 코드 0). 본문의 `목요일`을 `금요일`로 한 글자 바꾸면 해시가 달라져 `BAD signature`(종료 코드 1)가 된다.
5. **키 신뢰 (핑거프린트)** — Mallory가 Alice와 **똑같은 uid**(`Alice <alice@example.com>`)로 키를 만든다. 핑거프린트는 다르다. Mallory가 Alice인 척 서명한 것을 (가) Mallory 자기 키로 검증하면 `Good`이다 — 서명은 "이 키로 서명됨"만 말한다. 같은 서명을 (나) 진짜 Alice의 키만 담은 키링으로 `gpgv`에 넣으면 `No public key`로 거부된다(종료 코드 2). (다) 진짜 Alice의 서명은 그 키링에서 `Good`이다. 즉 **서명이 Good이어도 공개 키의 진위는 핑거프린트로 따로 확인해야 한다.**

## 실행

```
cd pgp
bash demo.sh
```

실행 환경은 **GnuPG(`gpg`) 2.4.5** (libgcrypt 1.9.4, Git for Windows 동봉)다. `gpg`와 `gpgv`가 PATH에 있어야 한다. 외부 라이브러리·네트워크·키 서버 접근은 없다. 스크립트는 `GNUPGHOME`을 `mktemp -d`로 잡아 시스템 키링을 건드리지 않고, 끝나면 임시 키링을 지운다(종료 트랩).

## 실행 출력

아래는 `bash demo.sh`를 한 번 실행한 출력이다. 키 ID·핑거프린트·날짜·서명 값은 실행마다 다르다(아래 「무엇이 매번 다른가」 참고).

```
=== 1. 키 생성 ===
pub   ed25519/1CC0FE6F45393D9F 2026-10-03 [SC]
      7B1E994ACC5F594B32588ECC1CC0FE6F45393D9F
uid                 [ultimate] Alice <alice@example.com>
sub   cv25519/000EF61A2EB1DFB4 2026-10-03 [E]

pub   ed25519/5766CF8163DFED14 2026-10-03 [SC]
      09F8A7EACDB04B8911F83E685766CF8163DFED14
uid                 [ultimate] Bob <bob@example.com>
sub   cv25519/7EBD8EF8F1DC622A 2026-10-03 [E]

=== 2. Alice가 서명하고 Bob의 공개 키로 암호화 ===
 25 note.txt
348 note.txt.gpg
373 total
# off=0 ctb=84 tag=1 hlen=2 plen=94
:pubkey enc packet: version 3, algo 18, keyid 7EBD8EF8F1DC622A
# off=96 ctb=d4 tag=20 hlen=3 plen=249 new-ctb
:aead encrypted packet: cipher=9 aead=2 cb=16
# off=118 ctb=a3 tag=8 hlen=1 plen=0 indeterminate
:compressed packet: algo=2
# off=120 ctb=90 tag=4 hlen=2 plen=13
:onepass_sig packet: keyid 1CC0FE6F45393D9F
# off=135 ctb=ac tag=11 hlen=2 plen=39
:literal data packet:
# off=176 ctb=88 tag=2 hlen=2 plen=136
:signature packet: algo 22, keyid 1CC0FE6F45393D9F
=== 3. Bob이 복호화하고 서명 확인 ===
회의는 목요일 3시
gpg: Signature made Sat, Oct  3, 2026 10:14:23 PM
gpg:                using EDDSA key 7B1E994ACC5F594B32588ECC1CC0FE6F45393D9F
gpg:                issuer "alice@example.com"
gpg: Good signature from "Alice <alice@example.com>" [ultimate]
--- Bob의 개인 키가 없는 제3자(Eve)의 키링에서 ---
# off=0 ctb=84 tag=1 hlen=2 plen=94
:pubkey enc packet: version 3, algo 18, keyid 7EBD8EF8F1DC622A
# off=96 ctb=d4 tag=20 hlen=3 plen=249 new-ctb
:aead encrypted packet: cipher=9 aead=2 cb=16
gpg: public key decryption failed: No secret key
gpg: decryption failed: No secret key
종료 코드 2
=== 4. 평문 서명과 변조 ===
-----BEGIN PGP SIGNED MESSAGE-----
Hash: SHA512

회의는 목요일 3시
-----BEGIN PGP SIGNATURE-----

iIgEARYKADAWIQR7HplKzF9ZSzJYjswcwP5vRTk9nwUCasD/rxIcYWxpY2VAZXhh
bXBsZS5jb20ACgkQHMD+b0U5PZ9tVQD9EMiWl5xiIpFmjdyRuVR/He5zJRAbfS1b
RZBVag9lvegA+wc5ReX4SkAxqywSPwekaClkbqAadAQrRS/qdODTjuML
=lIlz
-----END PGP SIGNATURE-----
--- 원본 검증 ---
gpg: Signature made Sat, Oct  3, 2026 10:14:23 PM
gpg:                using EDDSA key 7B1E994ACC5F594B32588ECC1CC0FE6F45393D9F
gpg:                issuer "alice@example.com"
gpg: Good signature from "Alice <alice@example.com>" [ultimate]
종료 코드 0
--- '목요일'을 '금요일'로 (한 글자) 바꾼 뒤 검증 ---
gpg: Signature made Sat, Oct  3, 2026 10:14:23 PM
gpg:                using EDDSA key 7B1E994ACC5F594B32588ECC1CC0FE6F45393D9F
gpg:                issuer "alice@example.com"
gpg: BAD signature from "Alice <alice@example.com>" [ultimate]
종료 코드 1
=== 5. 키 신뢰: Good 서명도 '진짜 Alice'를 증명하지 않는다 ===
--- 핑거프린트 대조: uid는 같아도 키는 다르다 ---
Alice   (먼저 생성) : 7B1E994ACC5F594B32588ECC1CC0FE6F45393D9F
Mallory (같은 uid)  : AC9F9098A81E4B1CD3CAF569378A7D3C4147F6A1
--- Mallory가 Alice인 척 서명 ---
--- (가) 사칭 서명을 Mallory 키로 검증: 암호학적으로는 Good ---
gpgv: Good signature from "Alice <alice@example.com>"
종료 코드 0
--- (나) 같은 사칭 서명을 '진짜 Alice' 키만 담은 키링으로 검증 ---
gpgv: Can't check signature: No public key
종료 코드 2
--- (다) 진짜 Alice의 서명을 그 키링으로 검증 ---
gpgv: Good signature from "Alice <alice@example.com>"
종료 코드 0
```

## 무엇이 매번 다른가

- **매번 다름:** 키 ID, 핑거프린트, 생성 날짜, `Signature made …` 시각, 평문 서명의 Base64 본문과 끝의 체크섬(`=lIlz`), 암호문 크기. 암호문은 서명 값 인코딩 길이에 따라 **347바이트와 348바이트**가 번갈아 나오고, 그에 맞춰 tag 20의 `plen`도 248/249로 움직인다.
- **항상 같음:** 패킷 tag 순서(1 → 20 → 8 → 4 → 11 → 2)와 알고리즘 번호(algo 18 ECDH, cipher 9 AES-256, aead 2 OCB, algo 2 ZLIB, algo 22 EdDSALegacy), `Good`/`BAD` 판정, 종료 코드(원본 0, 변조 1, 개인 키 없음 2, gpgv 거부 2), Eve의 복호화 실패, 그리고 (가)·(나)·(다) 세 검증 결과.

## 한계

- **역할 구분만 보인다.** 암호화(기밀성), 서명(무결성·출처), 키 신뢰(진위)가 각각 무엇을 보장하고 무엇을 못 하는지를 가른다. 세션 키 하이브리드의 내부 수치나 대칭·공개키 알고리즘의 상세는 다루지 않는다.
- **키 신뢰는 핑거프린트 대조와 "믿는 키만 담은 키링(`gpgv`)" 수준에서 멈춘다.** 키 서버, Web of Trust(상호 인증 서명), 인증서 체인은 다루지 않는다. 5단계의 `gpgv` 거부는 "신뢰할 키 집합을 직접 정하면 사칭 키가 걸러진다"를 보일 뿐, 신뢰 집합을 어떻게 안전하게 구성하는지는 범위 밖이다.
- **한 키링이 Alice·Bob·Mallory를 모두 연기한다.** 목록의 `[ultimate]`는 같은 키링에서 직접 만든 자기 키라 무조건 믿는다는 표시일 뿐, Mallory가 신뢰받는다는 뜻이 아니다(5단계의 `gpgv` 검증은 신뢰 모델 없이 키링만 본다). `gpgv`의 상대 경로 `--keyring`은 스크립트가 작업 디렉터리를 `GNUPGHOME`으로 바꿔 두어서 풀린다.
- **"한 바이트"가 아니라 "한 글자"다.** 바꾸는 `목`→`금`은 UTF-8에서 3바이트다. 검출에 필요한 변경 최소 단위가 1바이트라는 것과는 별개로, 여기서는 사람이 읽는 한 글자를 바꾼다.
- **GnuPG 2.4 기본값에 묶인다.** 암호화에 쓰이는 `aead encrypted packet`(tag 20, OCB)은 LibrePGP 계열 패킷이라 RFC 9580만 구현한 다른 도구가 읽는다는 보장이 없다. GnuPG끼리 주고받는 범위에서만 확인했다.
