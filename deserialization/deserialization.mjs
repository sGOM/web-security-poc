// 안전하지 않은 역직렬화(Insecure Deserialization) PoC — 프로토타입 오염
// 서버가 사용자 설정 JSON을 받아 서버의 기본 설정 객체에 "재귀 깊은 병합"한다.
// 역직렬화(JSON.parse)와 병합이 한 쌍이다. 입력이 __proto__ 키를 담으면,
// 키를 가리지 않는 재귀 병합은 그 키를 따라가 Object.prototype을 오염시킨다.
// 취약한 쪽(/vuln/merge)과 고친 쪽(/safe/merge)을 나란히 둔다.
//
// 중요(측정의 정직성): Object.prototype은 프로세스 전역이다. 한 프로세스에서
// 오염되면 같은 프로세스의 safe 측정까지 번진다. 그래서 vuln과 safe를 각각
// 별도 자식 프로세스에서 실행한다. node:child_process로 자기 자신을
// --child vuln / --child safe 인자로 재실행한다. 오염이 섞일 길이 없다.
//
// 서버는 127.0.0.1에만 뜨고, 공격 대상도 그 서버뿐이다. 외부 요청은 없다.

import http from "node:http";
import { fileURLToPath } from "node:url";
import { spawn } from "node:child_process";

// 공격 본문: JSON.parse 하면 own 키 "__proto__"를 가진 객체가 된다.
const ATTACK = '{"__proto__":{"isAdmin":true}}';

// 서버의 기본 설정. 요청마다 깨끗한 사본에 사용자 설정을 병합한다.
function freshConfig() {
  return { theme: "light", features: { beta: false } };
}

// --- 취약: 키를 가리지 않는 재귀 깊은 병합 --------------------------------
// target[key]를 __proto__ 키로 접근하면 target의 프로토타입(Object.prototype)에
// 닿고, 거기에 다시 병합하면서 전역 프로토타입이 오염된다.
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

// --- 고침: 위험한 키를 건너뛰는 재귀 깊은 병합 ----------------------------
// __proto__·constructor·prototype 키는 병합 대상에서 제외한다. 나머지 로직은
// 취약한 쪽과 같다. 다른 것은 이 한 줄의 키 가드뿐이다.
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

// --- 권한 게이트: 병합과 무관한, 방금 만든 평범한 빈 객체로 판정 -----------
// u는 공격 본문과 아무 관계도 없는 새 객체다. 전역 프로토타입이 오염되면
// u.isAdmin이 프로토타입 체인을 타고 true로 보여 게이트가 열린다.
function measure() {
  const u = {};               // 공격 본문과 아무 관계 없는 새 객체
  const isAdmin = u.isAdmin;  // 전역 프로토타입이 오염됐으면 상속으로 true가 된다
  const gate = u.isAdmin ? "열림(admin 통과)" : "닫힘(거부)";
  const polluted = Object.hasOwn(Object.prototype, "isAdmin"); // 전역 오염을 직접 측정
  return { isAdmin, gate, polluted };
}

// --- 자식 프로세스 한쪽(vuln 또는 safe)을 실행한다 ------------------------
function runChild(mode) {
  const merge = mode === "vuln" ? deepMergeVuln : deepMergeSafe;
  const route = `/${mode}/merge`;

  const server = http.createServer((req, res) => {
    const url = new URL(req.url, "http://127.0.0.1");
    if (req.method === "POST" && url.pathname === route) {
      let raw = "";
      req.on("data", (c) => (raw += c));
      req.on("end", () => {
        // 역직렬화: 신뢰할 수 없는 입력을 객체로 복원한다.
        const userConfig = JSON.parse(raw || "{}");
        // 병합: 서버의 기본 설정 사본에 사용자 설정을 깊은 병합한다.
        const merged = merge(freshConfig(), userConfig);
        res.writeHead(200, { "content-type": "application/json; charset=utf-8" });
        res.end(JSON.stringify(merged));
      });
      return;
    }
    res.writeHead(404, { "content-type": "application/json; charset=utf-8" });
    res.end(JSON.stringify({ error: "not found" }));
  });

  server.listen(0, "127.0.0.1", () => {
    const port = server.address().port;
    const before = measure();

    const data = ATTACK;
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        path: route,
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(data),
        },
      },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => {
          const after = measure();
          // 응답 본문에 isAdmin이 들어 있는지 문자열로 직접 확인한다. JSON.parse(body)로
          // 읽으면 오염된 vuln 자식에선 상속으로 true가 섞여 거짓 결과가 나온다.
          const bodyHasAdmin = body.includes("isAdmin");
          console.log(`── [자식 프로세스: ${mode}] pid=${process.pid} 127.0.0.1:${port} ──`);
          console.log(`  병합 전  ({}).isAdmin=${before.isAdmin}  Object.prototype 오염?=${before.polluted}  게이트 if(u.isAdmin) -> ${before.gate}`);
          console.log(`  POST ${route}  본문 ${ATTACK}`);
          console.log(`    -> ${res.statusCode} ${body}  (응답 본문에 isAdmin 포함?=${bodyHasAdmin})`);
          console.log(`  병합 후  ({}).isAdmin=${after.isAdmin}  Object.prototype 오염?=${after.polluted}  게이트 if(u.isAdmin) -> ${after.gate}`);
          // 결론은 mode가 아니라 측정값(after.polluted)에서 뽑는다.
          if (after.polluted) {
            console.log("  => 전역 Object.prototype이 오염됐다. 병합과 무관한 새 객체 {}가 admin이 된다.");
          } else {
            console.log("  => Object.prototype이 오염되지 않았다. 새 객체 {}는 admin이 아니다.");
          }
          server.close();
        });
      },
    );
    req.end(data);
  });
}

// --- 부모 프로세스: 두 자식을 순서대로 띄워 출력을 모은다 ------------------
function runParent() {
  const self = fileURLToPath(import.meta.url);
  console.log(process.version);
  console.log("Insecure Deserialization PoC — JSON 역직렬화 + 깊은 병합의 프로토타입 오염");
  console.log(`공격 본문: ${ATTACK}`);
  console.log("");
  console.log(`격리 방법: vuln과 safe를 각각 별도 자식 프로세스에서 실행한다 (부모 pid=${process.pid}).`);
  console.log("  (node:child_process로 자기 자신을 --child vuln / --child safe 로 재실행).");
  console.log("  Object.prototype은 프로세스 전역이라 한 번 오염되면 같은 프로세스의 safe");
  console.log("  측정까지 번진다. 프로세스를 나눠 오염이 섞일 길을 없앤다. 아래 각 줄의");
  console.log("  pid가 부모와도, 서로와도 다른 것이 세 프로세스임을 보인다.");
  console.log("");

  const spawnChild = (mode) =>
    new Promise((resolve) => {
      const child = spawn(process.execPath, [self, "--child", mode], {
        stdio: ["ignore", "inherit", "inherit"],
      });
      child.on("exit", resolve);
    });

  // 순차 실행: 출력이 섞이지 않도록 vuln이 끝난 뒤 safe를 띄운다.
  spawnChild("vuln").then(() => {
    console.log("");
    return spawnChild("safe");
  });
}

// --- 진입점 ----------------------------------------------------------------
const childIdx = process.argv.indexOf("--child");
if (childIdx !== -1) {
  runChild(process.argv[childIdx + 1]);
} else {
  runParent();
}
