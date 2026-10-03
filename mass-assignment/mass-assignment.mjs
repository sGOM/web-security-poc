// 대량 할당(Mass Assignment, 과도한 바인딩) PoC
// 서버가 요청 본문(JSON)을 객체에 통째로 복사해 저장할 때, 사용자가 건드리면
// 안 되는 필드(role 등)를 본문에 끼워 넣어 권한을 올리는 공격을 재현한다.
// 취약한 쪽(/vuln)과 고친 쪽(/safe)을 나란히 두고 같은 공격을 보낸다.
// 서버는 127.0.0.1에만 뜨고, 공격 대상도 그 서버뿐이다.

import http from "node:http";

// --- 1. 인메모리 데이터 ----------------------------------------------------
// 일반 사용자 alice. 처음엔 role='user'. 바꿀 수 있는 필드는 name·email뿐이고
// role은 서버만 바꿔야 하는 서버 전용 필드다.
function freshUser() {
  return { id: 1, name: "alice", email: "alice@example.com", role: "user" };
}

// /vuln 과 /safe 가 각자의 사용자 객체를 가진다. 같은 공격을 양쪽에 보내
// 결과가 갈리는 것을 한 실행에서 대조하기 위함이다.
let vulnUser = freshUser();
let safeUser = freshUser();

// --- 2. 서버: /vuln/update 와 /safe/update ------------------------------
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");

  const reply = (status, obj) => {
    res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
    res.end(JSON.stringify(obj));
  };

  // 케이스마다 두 사용자를 같은 초기 상태로 되돌려 깨끗하게 대조한다.
  if (req.method === "POST" && url.pathname === "/reset") {
    vulnUser = freshUser();
    safeUser = freshUser();
    reply(200, { ok: true });
    return;
  }

  if (
    req.method === "POST" &&
    (url.pathname === "/vuln/update" || url.pathname === "/safe/update")
  ) {
    let raw = "";
    req.on("data", (c) => (raw += c));
    req.on("end", () => {
      let body;
      try {
        body = JSON.parse(raw || "{}");
      } catch {
        reply(400, { error: "invalid json" });
        return;
      }

      if (url.pathname === "/vuln/update") {
        // 취약: 받은 본문을 객체에 통째로 덮어쓴다.
        // 본문에 role 같은 서버 전용 필드가 있으면 그대로 올라간다.
        Object.assign(vulnUser, body);
        reply(200, vulnUser);
        return;
      }

      // 고침: 허용된 필드만 뽑아 쓴다(allowlist).
      // name·email만 받고, role은 본문에 있어도 무시한다.
      const { name, email } = body;
      if (name !== undefined) safeUser.name = name;
      if (email !== undefined) safeUser.email = email;
      reply(200, safeUser);
    });
    return;
  }

  reply(404, { error: "not found" });
});

// --- 3. 같은 공격을 양쪽에 보내 결과를 대조한다 -----------------------------
function post(port, pathname, bodyObj) {
  return new Promise((resolve) => {
    const data = JSON.stringify(bodyObj);
    const req = http.request(
      {
        host: "127.0.0.1",
        port,
        path: pathname,
        method: "POST",
        headers: {
          "content-type": "application/json",
          "content-length": Buffer.byteLength(data),
        },
      },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () => resolve({ status: res.statusCode, json: JSON.parse(body) }));
      },
    );
    req.end(data);
  });
}

server.listen(0, "127.0.0.1", async () => {
  const port = server.address().port;
  console.log(process.version);
  console.log(`서버: 127.0.0.1:${port}`);
  console.log("사용자: alice (role=user). 바꿀 수 있는 필드는 name·email뿐, role은 서버만 바꾼다.");
  console.log("");

  const cases = [
    {
      label: "정상 수정",
      body: { name: "Alice", email: "alice@corp.com" },
    },
    {
      label: "권한 상승 (role 끼워 넣기)",
      body: { name: "Alice", email: "alice@corp.com", role: "admin" },
    },
  ];

  for (const { label, body } of cases) {
    await post(port, "/reset", {}); // 케이스마다 초기 상태로 되돌린다
    const vuln = await post(port, "/vuln/update", body);
    const safe = await post(port, "/safe/update", body);
    // role 값은 서버가 돌려준 객체에서 읽는다(하드코딩이 아니라 실제 저장된 값).
    console.log(`[${label}] 본문 ${JSON.stringify(body)}`);
    console.log(`  /vuln -> role=${vuln.json.role}  ${JSON.stringify(vuln.json)}`);
    console.log(`  /safe -> role=${safe.json.role}  ${JSON.stringify(safe.json)}`);
    console.log("");
  }

  server.close();
});
