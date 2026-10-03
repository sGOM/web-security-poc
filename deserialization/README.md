# 안전하지 않은 역직렬화 (Insecure Deserialization) — 프로토타입 오염

신뢰할 수 없는 입력을 객체로 복원(역직렬화)할 때, 입력이 객체 구조 자체를 조작하면 서버 로직이 바뀐다. Node.js에서 가장 흔한 구체 형태는 **JSON을 파싱해 기존 객체에 깊은 병합(deep merge)할 때 `__proto__` 키를 따라가 프로토타입을 오염(prototype pollution)시키는 것**이다. `JSON.parse('{"__proto__":{"isAdmin":true}}')`는 own 키 `__proto__`를 가진 객체를 만들고, 키를 가리지 않는 재귀 병합은 그 키를 `target.__proto__`(= `Object.prototype`)로 따라가 전역 프로토타입에 `isAdmin`을 심는다. 그러면 공격 본문과 아무 관계도 없는 평범한 빈 객체 `{}`까지 `isAdmin`을 상속해, `if (u.isAdmin)` 같은 권한 게이트가 열린다.

글: [안전하지 않은 역직렬화 — JSON 깊은 병합과 프로토타입 오염](https://sgom.github.io/posts/deserialization/)

## 무엇을 보이나

서버가 사용자 설정 JSON을 받아 서버의 기본 설정 객체(`{ theme, features }`)에 **재귀 깊은 병합**한다고 치자. 역직렬화(`JSON.parse`)와 병합이 한 쌍이다.

- `/vuln/merge`: 재귀 병합이 키를 가리지 않는다. 본문 `{"__proto__":{"isAdmin":true}}`를 병합하면 `Object.prototype.isAdmin`이 오염된다 (취약)
- `/safe/merge`: 병합 시 `__proto__`·`constructor`·`prototype` 키를 건너뛴다(키 가드). 오염되지 않는다 (고침)

공격을 측정 가능한 **로직 변화**로 보인다. 병합 뒤에, 그와 무관하게 **새로 만든 평범한 빈 객체** `const u = {}`가 `u.isAdmin`을 통해 `true`로 보이는지(프로토타입 체인으로 오염이 번졌는지) 확인하고, 권한 게이트 `if (u.isAdmin)`가 열리는지 출력한다. 병합 전후로 두 번 측정해 변화를 대조한다.

## 실행

Node.js 24. 의존성 없음. 서버는 `127.0.0.1`에만 뜬다.

```sh
node deserialization.mjs
```

```
v24.15.0
Insecure Deserialization PoC — JSON 역직렬화 + 깊은 병합의 프로토타입 오염
공격 본문: {"__proto__":{"isAdmin":true}}

격리 방법: vuln과 safe를 각각 별도 자식 프로세스에서 실행한다 (부모 pid=26124).
  (node:child_process로 자기 자신을 --child vuln / --child safe 로 재실행).
  Object.prototype은 프로세스 전역이라 한 번 오염되면 같은 프로세스의 safe
  측정까지 번진다. 프로세스를 나눠 오염이 섞일 길을 없앤다. 아래 각 줄의
  pid가 부모와도, 서로와도 다른 것이 세 프로세스임을 보인다.

── [자식 프로세스: vuln] pid=37240 127.0.0.1:50530 ──
  병합 전  ({}).isAdmin=undefined  Object.prototype 오염?=false  게이트 if(u.isAdmin) -> 닫힘(거부)
  POST /vuln/merge  본문 {"__proto__":{"isAdmin":true}}
    -> 200 {"theme":"light","features":{"beta":false}}  (응답 본문에 isAdmin 포함?=false)
  병합 후  ({}).isAdmin=true  Object.prototype 오염?=true  게이트 if(u.isAdmin) -> 열림(admin 통과)
  => 전역 Object.prototype이 오염됐다. 병합과 무관한 새 객체 {}가 admin이 된다.

── [자식 프로세스: safe] pid=38540 127.0.0.1:50532 ──
  병합 전  ({}).isAdmin=undefined  Object.prototype 오염?=false  게이트 if(u.isAdmin) -> 닫힘(거부)
  POST /safe/merge  본문 {"__proto__":{"isAdmin":true}}
    -> 200 {"theme":"light","features":{"beta":false}}  (응답 본문에 isAdmin 포함?=false)
  병합 후  ({}).isAdmin=undefined  Object.prototype 오염?=false  게이트 if(u.isAdmin) -> 닫힘(거부)
  => Object.prototype이 오염되지 않았다. 새 객체 {}는 admin이 아니다.
```

pid와 포트 번호는 실행마다 달라진다(위 출력의 `26124`·`37240`·`38540`, `50530`·`50532`). `v24.15.0`은 설치된 Node 24 마이너 버전에 따라 다르다. 나머지 출력은 고정이다.

## 읽는 법

- **병합 전**: 양쪽 다 `({}).isAdmin`이 `undefined`고 게이트는 닫혀 있다. 공격 전의 깨끗한 상태다.
- **병합 후 (vuln)**: 공격과 방어가 갈리는 지점이다. 취약한 쪽은 병합이 `__proto__` 키를 그대로 따라가 `Object.prototype.isAdmin = true`를 심는다. `Object.prototype 오염?`이 `false`→`true`로 바뀌고(이 값은 `Object.hasOwn(Object.prototype, "isAdmin")`을 직접 읽은 것이다), **병합과 무관한 새 객체** `{}`가 프로토타입 체인으로 `isAdmin`을 상속해 `true`가 되며, 게이트 `if (u.isAdmin)`가 열린다. 출력의 `=>` 결론 줄은 `mode`가 아니라 이 측정값에서 뽑으므로, 오염이 안 됐다면 "오염됐다"를 찍지 않는다.
- **병합 후 (safe)**: 고친 쪽은 `__proto__`를 병합에서 건너뛰므로 `Object.prototype`이 그대로다. `({}).isAdmin`은 여전히 `undefined`, `Object.prototype 오염?`은 `false`, 게이트는 닫힌 채다.
- **병합 결과 응답은 양쪽 다 똑같이 멀쩡하다** (`{"theme":"light","features":{"beta":false}}`). 오염은 반환된 설정 객체가 아니라 전역 `Object.prototype`에 생기므로, 응답만 봐서는 드러나지 않는다. 이것이 프로토타입 오염이 눈에 잘 안 띄는 이유다.

## 격리 방법

`Object.prototype`은 프로세스 전역이다. 한 프로세스 안에서 vuln을 먼저 돌려 오염시키면, 이어지는 safe 측정도 이미 오염된 프로토타입을 보게 돼 "safe도 오염됐다"는 거짓 결과가 나온다. 측정이 정직하려면 오염이 섞일 길을 없애야 한다.

이 PoC는 **vuln과 safe를 각각 별도 자식 프로세스에서 실행**한다. 부모 프로세스가 `node:child_process`의 `spawn`으로 자기 자신(`deserialization.mjs`)을 `--child vuln`, `--child safe` 인자로 두 번 재실행한다. 각 자식은 독립된 V8 인스턴스라 자기만의 `Object.prototype`을 가진다. vuln 자식이 오염돼도 safe 자식에는 닿지 못한다. 각 줄의 `pid`가 부모(`26124`)와도, 서로(`37240`·`38540`)와도 다른 것이 세 개의 프로세스임을 보여준다(`pid`는 실행마다 바뀐다). 부모는 vuln 자식이 끝난 뒤 safe 자식을 띄워 출력이 섞이지 않게 한다.

## 취약/고침 핵심 코드

취약한 쪽은 키를 가리지 않고 재귀 병합한다. `target[key]`를 `__proto__` 키로 접근하면 `target`의 프로토타입에 닿고, 거기에 다시 병합하면서 전역 `Object.prototype`이 오염된다.

```js
function deepMergeVuln(target, source) {
  for (const key of Object.keys(source)) {
    const val = source[key];
    if (val !== null && typeof val === "object") {
      if (target[key] === undefined || target[key] === null || typeof target[key] !== "object") {
        target[key] = {};
      }
      deepMergeVuln(target[key], val);
    } else {
      target[key] = val;
    }
  }
  return target;
}
```

고친 쪽은 위험한 키(`__proto__`·`constructor`·`prototype`)를 병합에서 건너뛴다. 다른 것은 이 한 줄의 키 가드뿐이다.

```js
const FORBIDDEN_KEYS = new Set(["__proto__", "constructor", "prototype"]);
function deepMergeSafe(target, source) {
  for (const key of Object.keys(source)) {
    if (FORBIDDEN_KEYS.has(key)) continue; // 위험한 키는 건너뛴다
    const val = source[key];
    if (val !== null && typeof val === "object") {
      if (target[key] === undefined || target[key] === null || typeof target[key] !== "object") {
        target[key] = {};
      }
      deepMergeSafe(target[key], val);
    } else {
      target[key] = val;
    }
  }
  return target;
}
```

게이트는 공격 본문과 무관한, 방금 만든 빈 객체로 판정한다. 하드코딩이 아니라 실제 프로토타입 체인을 읽는다.

```js
function measure() {
  const u = {};               // 공격 본문과 아무 관계 없는 새 객체
  const isAdmin = u.isAdmin;  // 전역 프로토타입이 오염됐으면 상속으로 true가 된다
  const gate = u.isAdmin ? "열림(admin 통과)" : "닫힘(거부)";
  const polluted = Object.hasOwn(Object.prototype, "isAdmin"); // 전역 오염을 직접 측정
  return { isAdmin, gate, polluted };
}
```

## 한계

- **이 PoC가 보이는 것은 "프로토타입 오염으로 인한 로직 변화"까지다.** 오염된 전역 프로토타입을 발판으로 삼는 RCE(원격 코드 실행)나 실제 가젯 체인(템플릿 엔진·`child_process` 옵션 등을 거쳐 코드 실행으로 잇는 것)은 다루지 않는다. 여기서는 권한 게이트 하나가 열리는 데까지만 재현한다.
- **키 가드는 `__proto__`·`constructor`·`prototype`만 막는다.** 이 세 키 차단이 깊은 병합의 1차 방어지만, 가장 견고한 방법은 신뢰 경계에서 스키마로 입력을 검증하는 것이다. 병합 대상을 `Object.create(null)`(프로토타입 없는 객체)로 두는 방법도 있으나, 이 PoC의 병합처럼 중첩 객체를 평범한 `{}`로 만드는 코드에서는 최상위만 null 프로토타입으로 둬도 막히지 않는다(`{"features":{"__proto__":{"isAdmin":true}}}` 같은 중첩 공격이 통한다 — Node v24.15.0에서 확인). 모든 중첩 객체까지 null 프로토타입이어야 한다. 이 PoC는 "키를 건너뛰는" 가드 한 가지만 보인다.
- **다른 역직렬화 형태는 다루지 않는다.** Java의 `ObjectInputStream`, Python의 `pickle`, PHP의 `unserialize()`처럼 직렬화 포맷 자체가 임의 객체를 복원하는 경우의 역직렬화는 메커니즘이 다르다. 이 PoC는 Node.js에서 가장 흔한 형태인 "JSON 파싱 + 깊은 병합"만 재현한다.

## 파일

- `deserialization.mjs`: 서버(`/vuln/merge`·`/safe/merge`), 취약/고친 깊은 병합, 자식 프로세스 격리와 측정을 한 파일에 담았다.
