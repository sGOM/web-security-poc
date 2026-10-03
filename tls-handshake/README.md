# TLS 핸드셰이크 (TLS Handshake)

HTTPS 연결은 두 가지를 끝내야 안전하다. 둘만 아는 키를 합의하는 것(키 교환), 그리고 상대가 접속하려던 그 서버가 맞다는 것을 확인하는 것(서버 인증)이다. 이 PoC는 사설 CA로 `localhost` 인증서를 만들어 `openssl s_server`/`s_client`로 핸드셰이크를 맺고, `-trace` 출력에서 **키 합의와 서버 인증이 각각 어느 메시지에서 일어나는지**, 그리고 **인증서 검증이 무엇을 보고 실패하는지**를 보인다. TLS 1.3과 1.2를 나란히 둔다.

글: [TLS 핸드셰이크 — 무엇을 합의하고 무엇을 증명하는가](https://sgom.github.io/posts/tls-handshake-basics/)

## 무엇을 보이나

`demo.sh`는 임시 디렉터리(`mktemp -d`)에 사설 CA와 그 CA가 서명한 `localhost` 인증서(SAN=`DNS:localhost`)를 만들고, `127.0.0.1:4433`에만 `s_server`를 띄운다. 끝나면 서버를 내리고 디렉터리를 지운다. 외부 네트워크는 쓰지 않는다. 다섯 절로 나뉜다.

1. **TLS 1.3 핸드셰이크 메시지** — `-trace`에서 메시지 이름과 방향만 뽑는다. ClientHello/ServerHello의 `key_share`로 왕복 한 번에 키를 합의하고, Certificate·CertificateVerify로 서버를 인증한다.
2. **TLS 1.2 핸드셰이크 메시지** — ServerKeyExchange/ClientKeyExchange가 따로 오가 왕복이 하나 더 든다. 합의된 암호 스위트(`Cipher is` 줄)도 같이 뽑는다.
3. **인증서 검증 성공/실패 대비(핵심 보안 포인트)** — 같은 서버에 세 가지로 접속한다.
   - CA 없이: `Verify return code: 21 (unable to verify the first certificate)` — 서명을 따라 올라갈 신뢰 앵커가 없다.
   - CA를 신뢰 앵커로 주면: `Verify return code: 0 (ok)`.
   - CA를 주고 `-verify_hostname example.com`으로 이름까지 검사하면: `Verify return code: 62 (hostname mismatch)` — 서명은 유효해도 인증서의 이름(`localhost`)이 접속하려던 이름과 다르다.
4. **검증 실패를 무시하는가** — `s_client`는 기본적으로 검증 실패를 보고만 하고 핸드셰이크를 계속한다(종료 코드 0). `-verify_return_error`를 주면 중단하고 코드 1로 끝난다. 취약(실패 무시) 대 정상(실패 시 거부)의 대비다.
5. **어느 메시지가 키 합의/서버 인증을 맡나 (측정)** — `-trace` 원문을 다시 읽어, 각 핸드셰이크 메시지가 평문/암호화 레코드 중 어디로 갔는지, 그 안에 `key_share`(키 교환 공개키)나 `Signature`(비밀키 보유 증명)가 들어 있는지를 표시한다. 라벨을 하드코딩하지 않고 trace에서 읽는다.

## 실행 환경

- **OpenSSL CLI.** OpenSSL 3.2.1(2024-01-30)에서 확인했다. `s_server`/`s_client`의 `-trace`는 OpenSSL이 `enable-ssl-trace`로 빌드돼 있어야 한다. 이 3.2.1 빌드에서는 동작했고, `-trace`가 없는 빌드라면 1·2·5절이 빈 줄로 나온다.
- 다른 의존성은 없다. `127.0.0.1:4433`을 쓴다. 그 포트가 이미 쓰이면 스크립트가 "서버가 응답하지 않는다"며 종료 코드 1로 끝난다.
- Git Bash(MSYS)에서도 돌도록 `MSYS_NO_PATHCONV=1`을 설정하고(Linux에서는 무시된다) 인증서 확장은 프로세스 치환 대신 실제 파일로 넘긴다. 순수 Linux/bash에서도 그대로 돈다.

## 실행

```bash
bash demo.sh
```

## 실제 출력

OpenSSL 3.2.1에서 다섯 번 돌려 아래 출력이 모두 같았다.

```text
=== 1. TLS 1.3 핸드셰이크
클라이언트 -> 서버 ClientHello
서버 -> 클라이언트 ServerHello
서버 -> 클라이언트 ChangeCipherSpec
서버 -> 클라이언트 EncryptedExtensions
서버 -> 클라이언트 Certificate
서버 -> 클라이언트 CertificateVerify
서버 -> 클라이언트 Finished
클라이언트 -> 서버 ChangeCipherSpec
클라이언트 -> 서버 Finished
서버 -> 클라이언트 NewSessionTicket
서버 -> 클라이언트 NewSessionTicket

=== 2. TLS 1.2 핸드셰이크
클라이언트 -> 서버 ClientHello
서버 -> 클라이언트 ServerHello
서버 -> 클라이언트 Certificate
서버 -> 클라이언트 ServerKeyExchange
서버 -> 클라이언트 ServerHelloDone
클라이언트 -> 서버 ClientKeyExchange
클라이언트 -> 서버 ChangeCipherSpec
클라이언트 -> 서버 Finished
서버 -> 클라이언트 NewSessionTicket
서버 -> 클라이언트 ChangeCipherSpec
서버 -> 클라이언트 Finished
New, TLSv1.2, Cipher is ECDHE-ECDSA-AES256-GCM-SHA384

=== 3. 인증서 검증
$ verify
Verify return code: 21 (unable to verify the first certificate)

$ verify -CAfile ca.crt
Verify return code: 0 (ok)

$ verify -CAfile ca.crt -verify_hostname example.com
Verify return code: 62 (hostname mismatch)

=== 4. 검증이 실패해도 s_client는 계속하는가
$ echo | openssl s_client -connect 127.0.0.1:4433 >/dev/null 2>&1; echo exit=$?
exit=0

$ echo | openssl s_client -connect 127.0.0.1:4433 -verify_return_error >/dev/null 2>&1; echo exit=$?
exit=1

=== 5. 어느 메시지가 키 합의와 서버 인증을 맡나 (trace 에서 측정)
[TLS 1.3]
  C->S ClientHello          [평문]
         -> ClientHello 안에 key_share (키 교환 공개키)
  S->C ServerHello          [평문]
         -> ServerHello 안에 key_share (키 교환 공개키)
  S->C EncryptedExtensions  [암호화]
  S->C Certificate          [암호화]
  S->C CertificateVerify    [암호화]
         -> CertificateVerify 안에 Signature (비밀키 보유 증명)
  S->C Finished             [암호화]
  C->S Finished             [암호화]
  S->C NewSessionTicket     [암호화]
  S->C NewSessionTicket     [암호화]
[TLS 1.2]
  C->S ClientHello          [평문]
  S->C ServerHello          [평문]
  S->C Certificate          [평문]
  S->C ServerKeyExchange    [평문]
         -> ServerKeyExchange 안에 Signature (비밀키 보유 증명)
  S->C ServerHelloDone      [평문]
  C->S ClientKeyExchange    [평문]
  C->S Finished             [암호화]
  S->C NewSessionTicket     [평문]
  S->C Finished             [암호화]
```

## 무엇을 읽어야 하나

- **키 합의는 Hello 메시지에서 끝난다(1.3).** 5절에서 `key_share`가 ClientHello와 ServerHello 양쪽에 들어 있다. 클라이언트가 첫 메시지에 이미 키 교환 공개키를 실어 보내므로, 서버의 첫 응답만으로 양쪽이 키를 계산한다. 1.2는 `key_share`가 없고 ServerKeyExchange/ClientKeyExchange가 따로 오가 왕복이 하나 더 든다.
- **서버 인증은 Signature가 한다.** 1.3은 CertificateVerify, 1.2는 ServerKeyExchange 안의 `Signature`가 "인증서에 대응하는 비밀키를 지금 가졌다"는 증명이다. 인증서 자체는 누구나 받아 볼 수 있어 복사만으로는 증명이 안 된다.
- **1.3은 서버 인증서를 암호화해 보낸다.** 5절에서 1.3의 Certificate·CertificateVerify가 `[암호화]`로 나온다. ServerHello 다음 레코드부터 trace가 `Inner Content Type`(암호화 레코드)으로 표시해서다. 1.2의 Certificate·ServerKeyExchange는 `[평문]`이고, 암호화는 ChangeCipherSpec 뒤의 Finished부터다.
- **검증은 서명 체인과 이름을 따로 본다.** 3절에서 CA가 없으면 21, 주면 0, 이름을 틀리게 검사하면 62다. `s_client`는 `-verify_hostname`을 주지 않으면 이름을 검사하지 않으므로 0은 체인만 통과한 것이다.
- **연결됐다고 검증이 통과한 것은 아니다.** 4절에서 CA 없이 붙어도 종료 코드는 0이다. `curl -k`, Python `requests`의 `verify=False`처럼 검증을 끄면 이 인증이 통째로 사라진다.

## 재현되는 부분과 달라지는 부분

- **재현된다:** 메시지 이름과 순서, 방향, `Verify return code`의 코드·문구(21/0/62), 종료 코드(0/1), 5절의 평문/암호화 라벨과 `key_share`·`Signature` 표시. TLS 1.3과 1.2의 차이. OpenSSL 3.2.1에서 다섯 번 모두 같았다.
- **달라진다:** `-trace` 원문에 나오는 세션 ID·인증서 지문·서명 값·타임스탬프는 매 실행 다르다(그래서 이름·방향만 뽑는다). 2절의 `Cipher is` 값은 EC 인증서를 써서 `ECDHE-ECDSA-AES256-GCM-SHA384`로 나왔으나, OpenSSL 빌드·버전에 따라 다른 스위트가 선택될 수 있다. 포트는 `127.0.0.1:4433` 고정이며, 그 포트가 이미 쓰이면 실행이 실패한다.

## 한계

- **암호 스위트 내부 수치나 키 스케줄(HKDF 등)은 다루지 않는다.** "어느 메시지에서 키 합의/서버 인증이 일어나는지"와 "인증서 검증이 무엇을 보고 실패하는지"만 보인다.
- **5절의 암호화 판정은 레코드 페이로드를 복호화해 확인한 것이 아니라 프로토콜이 암호화를 켜는 지점 기준이다.** TLS 1.3은 ServerHello 다음부터 핸드셰이크가 암호화 레코드(trace의 `Inner Content Type`)로 들어가므로 그것으로 판정한다. TLS 1.2는 암호화 전환을 ChangeCipherSpec이 알리고 이 전환이 Content Type 필드에는 드러나지 않으므로, 방향별로 ChangeCipherSpec을 지난 뒤의 메시지를 암호화로 본다. 그래서 1.2에서 Certificate·ServerKeyExchange는 평문, 클라이언트·서버의 Finished는 암호화, 서버 ChangeCipherSpec 앞에 오는 NewSessionTicket은 평문으로 나온다.
- **검증 실패 문구는 OpenSSL 메시지다.** 코드 번호(21/62)와 문구는 OpenSSL 버전에 따라 달라질 수 있다. 3.2.1에서 확인한 값을 싣는다.
- **TLS 1.3 라운드트립 1회는 서버가 클라이언트의 `key_share`를 받아들인 경우다.** 서버가 다른 그룹을 요구하는 HelloRetryRequest를 보내면 왕복이 하나 는다. 이 PoC는 그 경로를 재현하지 않는다.
- 사설 CA와 인증서는 임시 디렉터리에만 만들고 끝나면 지운다. 시스템 신뢰 저장소를 건드리지 않는다.
