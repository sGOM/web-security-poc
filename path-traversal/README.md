# 경로 조작 (Path Traversal, 디렉터리 순회)

서버가 사용자가 준 파일 이름을 공개 디렉터리 경로에 그대로 이어 붙여 읽어 주면, 공격자는 이름에 `../`를 넣어 공개 디렉터리 밖의 파일을 읽는다. 설정 파일, 키, `/etc/passwd` 같은 서버 내부 파일이 표적이 된다.

글: [경로 조작 — ../로 공개 디렉터리를 벗어나는 파일 읽기](https://sgom.github.io/posts/path-traversal/)

## 무엇을 보이나

임시 디렉터리 아래에 공개용 `public/`(안에 `hello.txt`, `doc.txt`)을 두고, 그 밖에 비밀 파일 `secret.txt`(내용 `TOP-SECRET`)를 둔다. 서버는 `?file=`로 파일 이름을 받아 읽어 준다.

- `/vuln`: `path.join(publicDir, file)`로 그대로 이어 붙여 읽는다 (취약)
- `/safe`: 이어 붙인 뒤 `path.resolve`로 정규화하고, 그 결과가 `publicDir` 경계 안인지 확인한다. 밖이면 403 (고침)

같은 입력 세 가지(정상 파일, 상위 탈출 `../secret.txt`, 절대 경로)를 양쪽에 보내 결과가 갈리는 것을 한 실행에서 대조한다.

## 실행

Node.js 24. 의존성 없음. 서버는 `127.0.0.1`에만 뜬다.

```sh
node path-traversal.mjs
```

```
v24.15.0
서버: 127.0.0.1:52900
공개 디렉터리: <tmp>/public  (hello.txt, doc.txt)
비밀 파일:     <tmp>/secret.txt  = "TOP-SECRET"

[정상 파일] file=hello.txt
  /vuln -> 200 "hello from public"
  /safe -> 200 "hello from public"

[상위 탈출] file=../secret.txt
  /vuln -> 200 "TOP-SECRET"
  /safe -> 403 "(403 경계 밖 접근 거절)"

[절대 경로] file=C:\Users\pooh6\AppData\Local\Temp\path-traversal-7smIAs\secret.txt
  /vuln -> 404 "(읽기 실패: ENOENT)"
  /safe -> 403 "(403 경계 밖 접근 거절)"
```

포트 번호와 임시 디렉터리 경로(`절대 경로` 입력에 찍히는 값)는 실행마다 달라진다.

## 읽는 법

- **정상 파일**: 양쪽 다 공개 파일을 읽어 준다. 고친 쪽이 멀쩡한 요청까지 막지는 않는다.
- **상위 탈출 `../secret.txt`**: `path.join`이 `..`를 정규화해 `publicDir`의 부모로 올라간다. 취약한 쪽은 `TOP-SECRET`을 꺼낸다. 고친 쪽은 정규화된 경로가 경계 밖이라 403으로 막는다. 이 한 줄이 공격과 방어가 갈리는 지점이다.
- **절대 경로**: `/safe`는 `path.resolve`가 절대 경로 세그먼트를 우선해 `publicDir` 밖으로 나가는 것을 경계 검사로 잡아 403으로 막는다. `/vuln`은 `path.join`이 절대 경로를 특별 취급하지 않고 그냥 이어 붙여(`publicDir` + 절대경로 문자열) 존재하지 않는 경로가 되어 404다. 즉 `join` 기반 취약 코드는 절대 경로로는 탈출하지 못하고 `../`로 탈출한다. 절대 경로 차단은 고친 쪽에서만 의미가 드러난다.

## 경계 검사 (고친 쪽 핵심)

```js
const resolved = path.resolve(publicDir, file);
const inside =
  resolved === publicDir || resolved.startsWith(publicDir + path.sep);
if (!inside) {
  res.writeHead(403);
  res.end("(403 경계 밖 접근 거절)\n");
  return;
}
```

`path.resolve`로 `..`와 절대 경로를 모두 정규화한 **뒤에** 경계를 검사한다. `publicDir` 그 자체이거나 `publicDir + 구분자`로 시작할 때만 안쪽으로 본다. `publicDir` 뒤에 구분자를 붙여 비교해야 `public-evil/` 같은 접두사 일치 우회를 막는다.

## 한계

- **경로 구분자는 OS마다 다르다.** 이 PoC는 Windows(Node.js v24.15.0)에서 실행해 출력을 담았다. `path.sep`, `path.join`, `path.resolve`는 실행 중인 OS 규칙을 따르므로, Windows에서는 `\`와 `/`를 둘 다 구분자로 보고 `C:\...` 절대 경로를 인식한다. 유닉스에서는 `/`만 구분자이고 `\`는 파일 이름의 보통 글자다. 유닉스에서 같은 스크립트를 돌리면 `절대 경로` 입력은 `/tmp/...secret.txt` 꼴이 되고, `/vuln`의 결과(`join`이 절대 경로를 이어 붙여 ENOENT)와 `/safe`의 403은 동일하게 재현된다. 유닉스 실행 출력은 직접 확인하지 않았다.
- **심볼릭 링크는 다루지 않는다.** `publicDir` 안에 바깥을 가리키는 심링크가 있으면 경로 문자열 검사(`startsWith`)는 통과하지만 실제로는 경계 밖을 읽는다. 실무에서는 `fs.realpath`로 심링크까지 푼 실제 경로로 검사한다. 이 PoC는 그 경로를 재현하지 않는다.
- **URL 인코딩 우회는 다루지 않는다.** `%2e%2e%2f` 같은 입력은 이 서버가 `URL`로 파싱하는 단계에서 이미 디코딩된 `../`로 들어온다. 그 앞단(웹 서버·프레임워크의 디코딩 순서)에서 생기는 이중 디코딩 문제는 범위 밖이다.
- 비밀 파일 내용은 무해한 리터럴(`TOP-SECRET`)이다. 실제 공격의 파괴적 동작은 재현하지 않는다.

## 파일

- `path-traversal.mjs`: 디렉터리 준비, 서버(`/vuln`·`/safe`), 공격 대조 데모를 한 파일에 담았다.
