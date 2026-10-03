#!/usr/bin/env bash
# 로컬 openssl 서버·클라이언트로 TLS 1.3과 1.2 핸드셰이크 메시지, 인증서 검증 결과,
# 그리고 어느 메시지가 키 합의/서버 인증을 맡는지 -trace 에서 측정해 보인다.
#   bash demo.sh
#
# 모든 서버는 127.0.0.1 에만 뜨고, 접속 대상도 그 서버뿐이다. 외부 네트워크는 쓰지 않는다.
set -u

# Git Bash(MSYS): "/CN=..." 인자가 Windows 경로로 바뀌는 것을 막는다. Linux 에서는 무시된다.
export MSYS_NO_PATHCONV=1

HOST=127.0.0.1
PORT=4433
WORK="$(mktemp -d)"
SERVER=""

cleanup() {
  [ -n "$SERVER" ] && kill "$SERVER" 2>/dev/null
  wait "$SERVER" 2>/dev/null
  rm -rf "$WORK"
}
trap cleanup EXIT
cd "$WORK" || exit 1

run() { printf '$ %s\n' "$*"; eval "$*" 2>&1; echo; }

# --- 사설 CA 와, 그 CA 가 서명한 localhost 인증서 (임시 디렉터리에만 둔다) ---
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 1 \
  -subj "/CN=Test CA" -keyout ca.key -out ca.crt 2>/dev/null
openssl req -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
  -subj "/CN=localhost" -keyout server.key -out server.csr 2>/dev/null
# 네이티브 Windows openssl 은 프로세스 치환(<(...))의 /dev/fd 를 못 읽어 실제 파일을 쓴다.
printf 'subjectAltName=DNS:localhost\n' > ext.cnf
openssl x509 -req -in server.csr -CA ca.crt -CAkey ca.key -days 1 \
  -extfile ext.cnf -out server.crt 2>/dev/null

# --- 서버는 127.0.0.1 에만 띄운다 ---
openssl s_server -accept "$HOST:$PORT" -cert server.crt -key server.key -www >/dev/null 2>&1 &
SERVER=$!

# 서버가 응답할 때까지 최대 5초 대기 (포트가 이미 쓰이면 명확히 끝낸다)
ready=""
for _ in $(seq 1 25); do
  if echo | openssl s_client -connect "$HOST:$PORT" -CAfile ca.crt >/dev/null 2>&1; then ready=1; break; fi
  sleep 0.2
done
[ -z "$ready" ] && { echo "서버가 $HOST:$PORT 에서 응답하지 않는다 (포트 사용 중일 수 있다)"; exit 1; }

# -trace 출력에서 핸드셰이크 메시지 이름과 방향만 뽑는다.
# stdin 을 1초 열어 둬야 핸드셰이크 뒤의 세션 티켓까지 받고 끊는다.
messages() {
  sleep 1 | openssl s_client -connect "$HOST:$PORT" "$@" -trace 2>&1 | awk '
    /^Sent TLS Record/     { dir = "클라이언트 -> 서버" }
    /^Received TLS Record/ { dir = "서버 -> 클라이언트" }
    /Content Type = ChangeCipherSpec/ { print dir, "ChangeCipherSpec" }
    /^    [A-Za-z]+, Length=/ { sub(/,.*/, ""); sub(/^ +/, ""); print dir, $0 }'
}

echo "=== 1. TLS 1.3 핸드셰이크"
messages -tls1_3 -CAfile ca.crt

echo; echo "=== 2. TLS 1.2 핸드셰이크"
messages -tls1_2 -CAfile ca.crt
echo | openssl s_client -connect "$HOST:$PORT" -tls1_2 -CAfile ca.crt 2>&1 | grep -m1 'Cipher is'

echo; echo "=== 3. 인증서 검증"
verify() { echo | openssl s_client -connect "$HOST:$PORT" "$@" 2>&1 | grep 'Verify return code' | sed 's/^ *//' | awk '!seen[$0]++'; }
run "verify"
run "verify -CAfile ca.crt"
run "verify -CAfile ca.crt -verify_hostname example.com"

echo "=== 4. 검증이 실패해도 s_client 는 계속하는가"
run "echo | openssl s_client -connect $HOST:$PORT >/dev/null 2>&1; echo exit=\$?"
run "echo | openssl s_client -connect $HOST:$PORT -verify_return_error >/dev/null 2>&1; echo exit=\$?"

echo "=== 5. 어느 메시지가 키 합의와 서버 인증을 맡나 (trace 에서 측정)"
# 각 핸드셰이크 메시지가 평문/암호화 레코드 중 어디로 갔는지, 그 안에 key_share(키 교환 공개키)나
# Signature(비밀키 보유 증명)가 들어 있는지를 trace 원문에서 읽어 표시한다. 라벨을 하드코딩하지 않는다.
annotate() {
  sleep 1 | openssl s_client -connect "$HOST:$PORT" "$@" -trace 2>&1 | awk '
    /^  Content Type = Handshake/       { enc = "평문" }
    /^  Inner Content Type = Handshake/ { enc = "암호화" }
    /^    [A-Za-z]+, Length=/ {
      name = $0; sub(/,.*/, "", name); sub(/^ +/, "", name);
      cur = name;
      printf "  %-20s [%s]\n", name, enc;
      next
    }
    /extension_type=key_share/ { if (cur != "") print "    ↳ " cur " 안에 key_share (키 교환 공개키)" }
    /^ +Signature \(len=/      { if (cur != "") print "    ↳ " cur " 안에 Signature (비밀키 보유 증명)" }'
}
echo "[TLS 1.3]"
annotate -tls1_3 -CAfile ca.crt
echo "[TLS 1.2]"
annotate -tls1_2 -CAfile ca.crt
