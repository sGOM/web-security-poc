# 대량 할당 (Mass Assignment, 과도한 바인딩)

서버가 요청 본문(JSON)을 객체에 통째로 복사해 저장하면, 사용자가 건드리면 안 되는 필드까지 본문에 끼워 넣어 바꿀 수 있다. 프로필 수정 폼이 `name`·`email`만 보내는 걸 전제로 짰더라도, 공격자는 폼을 거치지 않고 `role: "admin"`을 본문에 추가해 직접 요청한다. 서버가 받은 필드를 가리지 않으면 권한이 올라간다. Rails의 `params` 일괄 할당, Spring의 커맨드 객체 바인딩, JS의 `Object.assign`처럼 "본문을 객체에 그대로 흘려 넣는" 코드가 표적이 된다.

글: [대량 할당 — 요청 본문을 객체에 통째로 복사할 때](https://sgom.github.io/posts/mass-assignment/)

## 무엇을 보이나

인메모리 사용자 alice를 둔다. `{ id, name, email, role }`이고 처음엔 `role: "user"`다. 정상적으로 바꿀 수 있는 필드는 `name`·`email`뿐이고 `role`은 서버만 바꿔야 하는 서버 전용 필드다.

- `/vuln/update`: 받은 본문을 `Object.assign(user, body)`로 통째로 덮어쓴다 (취약)
- `/safe/update`: 허용된 필드(`name`·`email`)만 뽑아 쓴다(allowlist). `role`은 본문에 있어도 무시한다 (고침)

같은 본문을 양쪽에 보낸다. 정상 수정(`{name, email}`)과 권한 상승(`{name, email, role:"admin"}`) 두 가지다. 케이스마다 두 사용자를 같은 초기 상태로 되돌린 뒤, 수정 후 서버가 돌려준 객체에서 `role` 값을 읽어 출력한다. 취약한 쪽은 `user`→`admin`으로 올라가고, 고친 쪽은 `user`를 유지한다.

## 실행

Node.js 24. 의존성 없음. 서버는 `127.0.0.1`에만 뜬다.

```sh
node mass-assignment.mjs
```

```
v24.15.0
서버: 127.0.0.1:56615
사용자: alice (role=user). 바꿀 수 있는 필드는 name·email뿐, role은 서버만 바꾼다.

[정상 수정] 본문 {"name":"Alice","email":"alice@corp.com"}
  /vuln -> role=user  {"id":1,"name":"Alice","email":"alice@corp.com","role":"user"}
  /safe -> role=user  {"id":1,"name":"Alice","email":"alice@corp.com","role":"user"}

[권한 상승 (role 끼워 넣기)] 본문 {"name":"Alice","email":"alice@corp.com","role":"admin"}
  /vuln -> role=admin  {"id":1,"name":"Alice","email":"alice@corp.com","role":"admin"}
  /safe -> role=user  {"id":1,"name":"Alice","email":"alice@corp.com","role":"user"}
```

포트 번호는 실행마다 달라진다. `v24.15.0`은 설치된 Node 24 마이너 버전에 따라 다르다. 나머지 출력은 고정이다.

## 읽는 법

- **정상 수정 (`{name, email}`)**: 양쪽 다 `name`·`email`이 바뀌고 `role`은 `user` 그대로다. 고친 쪽이 멀쩡한 수정까지 막지는 않는다.
- **권한 상승 (`{name, email, role:"admin"}`)**: 공격과 방어가 갈리는 지점이다. 본문에 `role:"admin"`을 끼웠을 때, 취약한 쪽은 `Object.assign`이 받은 키를 가리지 않고 전부 덮어쓰니 `role`이 `admin`으로 올라간다. 고친 쪽은 `name`·`email`만 뽑아 쓰므로 본문의 `role`은 버려지고 `user`를 유지한다. 공격자는 수정 폼을 거치지 않고 JSON에 필드 하나를 더 넣었을 뿐이다.

## 허용 필드만 뽑기 (고친 쪽 핵심)

```js
// 고침: 허용된 필드만 뽑아 쓴다(allowlist).
// name·email만 받고, role은 본문에 있어도 무시한다.
const { name, email } = body;
if (name !== undefined) safeUser.name = name;
if (email !== undefined) safeUser.email = email;
reply(200, safeUser);
```

취약한 쪽은 본문을 통째로 흘려 넣는다.

```js
// 취약: 받은 본문을 객체에 통째로 덮어쓴다.
// 본문에 role 같은 서버 전용 필드가 있으면 그대로 올라간다.
Object.assign(vulnUser, body);
reply(200, vulnUser);
```

차이는 "본문의 키를 그대로 믿느냐"다. 취약한 쪽은 `body`의 모든 키를 사용자 객체에 복사한다. 고친 쪽은 서버가 받을 키를 코드에 고정(`name`·`email`)하고, 그 밖의 키는 구조 분해에서 아예 빠지므로 `role`이 본문에 있어도 닿지 못한다. 핵심은 **서버가 허용할 필드를 명시(allowlist)하는 것**이다. 반대로 "`role`만 빼자"는 거부 목록(denylist)은 새 서버 전용 필드(`isAdmin`, `balance`)가 늘 때마다 빠뜨리기 쉬워 권장하지 않는다.

## 한계

- **allowlist는 수정 가능 필드만 본다.** 여기서는 `name`·`email`을 서버 코드에 직접 썼다. 실무에선 역할·상황마다 수정 가능 필드가 다르다(관리자는 `role`도 바꾼다). 그때는 사용자 입력 바인딩과 권한 있는 변경을 분리된 경로로 처리한다. 이 PoC는 "일반 사용자용 수정 경로" 하나만 보인다.
- **ORM·프레임워크 자동 바인딩은 재현하지 않는다.** 실제 사고는 Rails `update(params)`, Spring 커맨드 객체, Mongoose 전체 도큐먼트 저장처럼 프레임워크가 요청을 엔티티에 자동으로 매핑하는 데서도 같은 문제가 생긴다. 여기서는 그 메커니즘을 `Object.assign` 한 줄로 축약했다. 프레임워크별 방어책(`strong parameters`, `@JsonIgnore`, DTO 분리)은 다루지 않는다.
- **프로토타입 오염은 다루지 않는다.** 본문에 `__proto__` 키를 넣는 것은 대량 할당과 인접한 별개 주제라 이 PoC의 스크립트에 넣지 않았다(범위는 `role`뿐). 다만 `Object.assign`은 [[Set]]으로 복사해 setter를 부르므로, `Object.assign(u, JSON.parse('{"__proto__":{"isAdmin":true}}'))`는 `u`의 프로토타입을 바꾼다. Node v24.15.0에서 확인: `u.isAdmin`은 `true`, `Object.keys(u)`에는 `__proto__`가 안 들어가고 `JSON.stringify(u)`에도 안 보이며(그래서 이 PoC의 "응답에서 role을 읽는" 측정 방식으로는 드러나지 않는다), `Object.prototype` 자체는 오염되지 않는다(`({}).isAdmin`은 `undefined`). 이 사용자 모델엔 중첩 필드가 없어 중첩 주입도 다루지 않는다.
- **인증·세션은 생략했다.** 공격의 본질이 "로그인한 사용자가 자기 요청에 금지 필드를 끼우는 것"이라, 어느 사용자인지 식별하는 부분은 단일 사용자 alice로 축약했다.

## 파일

- `mass-assignment.mjs`: 인메모리 사용자, 서버(`/vuln/update`·`/safe/update`), 공격 대조 데모를 한 파일에 담았다.
