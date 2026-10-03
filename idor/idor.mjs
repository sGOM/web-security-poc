// IDOR(Insecure Direct Object Reference, 접근 제어 누락) PoC
// 로그인한 사용자가 리소스 ID를 바꿔 남의 리소스에 접근하는 공격을 재현한다.
// 서버가 "로그인했는가"는 보지만 "이 리소스가 그 사용자 것인가"(소유자 확인)를
// 안 보면 뚫린다. 취약한 쪽(/vuln)과 고친 쪽(/safe)을 나란히 두고 같은 공격을 보낸다.
// 서버는 127.0.0.1에만 뜨고, 공격 대상도 그 서버뿐이다.

import http from "node:http";

// --- 1. 인메모리 데이터 ----------------------------------------------------
// 주문 3건. order 1·2는 alice, order 3은 bob 소유다.
// 각 주문에 소유자(ownerId)와 민감한 내용(카드 끝자리, 주소)을 둔다.
const orders = {
  1: { ownerId: "alice", card: "**** 1111", address: "서울시 A구 1로" },
  2: { ownerId: "alice", card: "**** 2222", address: "서울시 A구 2로" },
  3: { ownerId: "bob", card: "**** 9999", address: "부산시 B구 9로" },
};

// 세션: 로그인 흉내. Authorization 헤더의 토큰으로 사용자를 식별한다.
const sessions = {
  "sess-alice": "alice",
  "sess-bob": "bob",
};

function currentUser(req) {
  const token = (req.headers["authorization"] ?? "").replace(/^Bearer\s+/i, "");
  return sessions[token] ?? null; // 없으면 비로그인
}

// --- 2. 서버: /vuln/order 와 /safe/order --------------------------------
const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  const id = url.searchParams.get("id") ?? "";
  const user = currentUser(req);

  const reply = (status, obj) => {
    res.writeHead(status, { "content-type": "application/json; charset=utf-8" });
    res.end(JSON.stringify(obj));
  };

  // 두 경로 모두 먼저 로그인을 확인한다. 비로그인은 401.
  if (!user) {
    reply(401, { error: "login required" });
    return;
  }

  if (url.pathname === "/vuln/order") {
    // 취약: 로그인만 확인하고 ID로 바로 주문을 꺼내 준다.
    // 그 주문이 현재 사용자 것인지 보지 않는다.
    const order = orders[id];
    if (!order) {
      reply(404, { error: "not found" });
      return;
    }
    reply(200, { id: Number(id), ...order });
    return;
  }

  if (url.pathname === "/safe/order") {
    // 고침: 로그인 + 그 주문의 ownerId가 현재 세션 사용자와 같은지 확인한다.
    const order = orders[id];
    // 존재하지 않거나 남의 주문이면 똑같이 404로 응답해 존재 여부를 숨긴다.
    if (!order || order.ownerId !== user) {
      reply(404, { error: "not found" });
      return;
    }
    reply(200, { id: Number(id), ...order });
    return;
  }

  reply(404, { error: "not found" });
});

// --- 3. 같은 공격을 양쪽에 보내 결과를 대조한다 -----------------------------
function get(port, pathWithQuery, token) {
  return new Promise((resolve) => {
    http.get(
      {
        host: "127.0.0.1",
        port,
        path: pathWithQuery,
        headers: token ? { authorization: `Bearer ${token}` } : {},
      },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () =>
          resolve({ status: res.statusCode, body: body.trim() }),
        );
      },
    );
  });
}

server.listen(0, "127.0.0.1", async () => {
  const port = server.address().port;
  console.log(process.version);
  console.log(`서버: 127.0.0.1:${port}`);
  console.log("주문: 1·2 = alice 소유, 3 = bob 소유");
  console.log("세션: alice 로그인 (토큰 sess-alice)");
  console.log("");

  // alice 세션으로 자기 주문(1)과 남의 주문(3)을 양쪽 경로에 요청한다.
  const cases = [
    { label: "자기 주문", id: 1 },
    { label: "남의 주문", id: 3 },
  ];
  for (const { label, id } of cases) {
    const q = `?id=${id}`;
    const vuln = await get(port, `/vuln/order${q}`, "sess-alice");
    const safe = await get(port, `/safe/order${q}`, "sess-alice");
    console.log(`[${label}] alice가 id=${id} 요청`);
    console.log(`  /vuln -> ${vuln.status} ${vuln.body}`);
    console.log(`  /safe -> ${safe.status} ${safe.body}`);
    console.log("");
  }

  // 순차 ID 열거: alice가 id=1..3을 훑어 어디까지 보이는지 대조한다.
  console.log("[순차 ID 열거] alice가 id=1..3을 훑는다");
  for (const id of [1, 2, 3]) {
    const vuln = await get(port, `/vuln/order?id=${id}`, "sess-alice");
    const safe = await get(port, `/safe/order?id=${id}`, "sess-alice");
    const owner = orders[id].ownerId;
    console.log(
      `  id=${id} (${owner} 소유)  /vuln -> ${vuln.status}  /safe -> ${safe.status}`,
    );
  }
  console.log("");

  server.close();
});
