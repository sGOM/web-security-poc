#!/usr/bin/env bash
# PGP PoC — GnuPG(gpg)로 공개키 암호화(세션 키 하이브리드), 서명 검증(Good/BAD),
# 키 신뢰(핑거프린트)를 빈 임시 키링에서 직접 재현한다.
# 시스템 키링은 건드리지 않고(GNUPGHOME=mktemp), 외부 네트워크/키서버 접근도 없다.
set -e
exec 2>&1   # bash demo.sh (리다이렉트 없이)만으로 README 출력이 그대로 나오도록 stderr를 합친다

export GNUPGHOME=$(mktemp -d)
EVE=$(mktemp -d)   # Bob의 개인 키가 없는 제3자의 키링
trap 'gpgconf --kill gpg-agent >/dev/null 2>&1; \
      gpgconf --homedir "$EVE" --kill gpg-agent >/dev/null 2>&1; \
      rm -rf "$GNUPGHOME" "$EVE"' EXIT
cd "$GNUPGHOME"   # gpgv의 상대 경로 --keyring이 이 디렉터리를 기준으로 풀린다

# batch 모드 + 빈 passphrase: 데모가 멈추지 않게 한다. 실제 키에는 passphrase를 건다.
g() { gpg --batch --yes --quiet --pinentry-mode loopback --passphrase "" "$@"; }

# --with-colons 출력에서 각 공개키의 '주 키' 핑거프린트만 뽑는다(서브키 fpr 제외).
primary_fprs() { gpg --list-keys --with-colons "$1" 2>/dev/null \
  | awk -F: '/^pub:/{p=1} /^fpr:/{ if(p){print $10; p=0} }'; }

echo "=== 1. 키 생성 ==="
g --quick-gen-key "Alice <alice@example.com>" default default never 2>/dev/null
g --quick-gen-key "Bob <bob@example.com>" default default never 2>/dev/null
g --list-keys --keyid-format long alice@example.com bob@example.com

echo "=== 2. Alice가 서명하고 Bob의 공개 키로 암호화 ==="
echo "회의는 목요일 3시" > note.txt
g --local-user alice@example.com --recipient bob@example.com \
   --sign --encrypt --output note.txt.gpg note.txt
wc -c note.txt note.txt.gpg
# 세션 키가 공개키로 감싸였고(tag 1), 서명/본문은 암호문(tag 20) 안에 든 구조를 패킷으로 본다.
gpg --list-packets note.txt.gpg 2>/dev/null | grep -E '^(:|# off)'

echo "=== 3. Bob이 복호화하고 서명 확인 ==="
g --decrypt note.txt.gpg

echo "--- Bob의 개인 키가 없는 제3자(Eve)의 키링에서 ---"
g --export alice@example.com bob@example.com > pub.gpg
gpg --homedir "$EVE" --batch --quiet --import pub.gpg 2>/dev/null
# 바깥에서 보이는 것: 세션 키(tag 1)와 암호문(tag 20) 두 패킷뿐. 안쪽은 못 연다.
gpg --homedir "$EVE" --list-packets note.txt.gpg 2>/dev/null | grep -E '^(:|# off)'
gpg --homedir "$EVE" --batch --quiet --pinentry-mode loopback \
    --decrypt note.txt.gpg 2>&1 | grep -E 'decrypt|secret key'
echo "종료 코드 ${PIPESTATUS[0]}"

echo "=== 4. 평문 서명과 변조 ==="
g --local-user alice@example.com --clearsign --output note.txt.asc note.txt
cat note.txt.asc   # 본문은 평문 그대로 두고 아래에 서명을 붙인다 (ASCII Armor)
rm -f note.txt     # 데이터 파일이 있으면 gpg가 clear-sign을 detached로 오인해 경고를 낸다
echo "--- 원본 검증 ---"
g --verify note.txt.asc && echo "종료 코드 0"
echo "--- '목요일'을 '금요일'로 (한 글자) 바꾼 뒤 검증 ---"
cp note.txt.asc note.tampered.asc
sed -i 's/목요일/금요일/' note.tampered.asc
g --verify note.tampered.asc || echo "종료 코드 $?"

echo "=== 5. 키 신뢰: Good 서명도 '진짜 Alice'를 증명하지 않는다 ==="
# Mallory가 Alice와 똑같은 uid로 키를 만든다 (사칭).
g --quick-gen-key "Alice <alice@example.com>" default default never 2>/dev/null
ALICE_FPR=$(primary_fprs alice@example.com | head -1)
MALLORY_FPR=$(primary_fprs alice@example.com | tail -1)
echo "--- 핑거프린트 대조: uid는 같아도 키는 다르다 ---"
echo "Alice   (먼저 생성) : $ALICE_FPR"
echo "Mallory (같은 uid)  : $MALLORY_FPR"

echo "--- Mallory가 Alice인 척 서명 ---"
echo "계좌를 바꿨습니다" > fake.txt
g --local-user "${MALLORY_FPR}!" --clearsign --output fake.txt.asc fake.txt
rm -f fake.txt

# 검증자는 '신뢰하는 키'만 담은 키링으로 검증한다(gpgv는 신뢰모델 없이 그 키링만 본다).
gpg --export "$ALICE_FPR"   > alice-only.gpg
gpg --export "$MALLORY_FPR" > mallory-only.gpg

echo "--- (가) 사칭 서명을 Mallory 키로 검증: 암호학적으로는 Good ---"
gpgv --keyring mallory-only.gpg fake.txt.asc 2>&1 | grep -E 'Good|BAD|public key'
echo "종료 코드 ${PIPESTATUS[0]}"
echo "--- (나) 같은 사칭 서명을 '진짜 Alice' 키만 담은 키링으로 검증 ---"
gpgv --keyring alice-only.gpg fake.txt.asc 2>&1 | grep -E 'Good|BAD|public key'
echo "종료 코드 ${PIPESTATUS[0]}"
echo "--- (다) 진짜 Alice의 서명을 그 키링으로 검증 ---"
gpgv --keyring alice-only.gpg note.txt.asc 2>&1 | grep -E 'Good|BAD|public key'
echo "종료 코드 ${PIPESTATUS[0]}"
