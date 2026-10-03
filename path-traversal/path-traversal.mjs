// 경로 조작(Path Traversal) PoC
// 서버가 사용자가 준 파일 이름으로 파일을 읽어 줄 때, `../`가 든 이름으로
// 공개 디렉터리 밖의 파일을 읽는 공격을 재현한다.
// 취약한 쪽(/vuln)과 고친 쪽(/safe)을 나란히 두고 같은 공격을 보낸다.
// 서버는 127.0.0.1에만 뜨고, 공격 대상도 그 서버뿐이다.

import http from "node:http";
import fs from "node:fs";
import path from "node:path";
import os from "node:os";

// --- 1. 공개 디렉터리와 비밀 파일 준비 -------------------------------------
// 임시 디렉터리 root/ 아래에 공개용 public/ 을 두고,
// public/ 밖(root/ 바로 아래)에 비밀 파일을 둔다.
const root = fs.mkdtempSync(path.join(os.tmpdir(), "path-traversal-"));
const publicDir = path.join(root, "public");
fs.mkdirSync(publicDir);
fs.writeFileSync(path.join(publicDir, "hello.txt"), "hello from public\n");
fs.writeFileSync(path.join(publicDir, "doc.txt"), "public document\n");

const secretPath = path.join(root, "secret.txt");
fs.writeFileSync(secretPath, "TOP-SECRET\n");

// --- 2. 서버: ?file= 로 파일 이름을 받아 읽어 준다 --------------------------
function readFileReply(res, filePath) {
  try {
    const data = fs.readFileSync(filePath, "utf8");
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    res.end(data);
  } catch (e) {
    res.writeHead(404, { "content-type": "text/plain; charset=utf-8" });
    res.end(`(읽기 실패: ${e.code})\n`);
  }
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, "http://127.0.0.1");
  const file = url.searchParams.get("file") ?? "";

  if (url.pathname === "/vuln") {
    // 취약: 사용자 입력을 그대로 이어 붙인다. `../`가 그대로 정규화되어
    // publicDir 밖으로 빠져나간다.
    const filePath = path.join(publicDir, file);
    readFileReply(res, filePath);
    return;
  }

  if (url.pathname === "/safe") {
    // 고침: 이어 붙인 뒤 정규화하고, 그 결과가 publicDir 경계 안인지 확인한다.
    const resolved = path.resolve(publicDir, file);
    const inside =
      resolved === publicDir || resolved.startsWith(publicDir + path.sep);
    if (!inside) {
      res.writeHead(403, { "content-type": "text/plain; charset=utf-8" });
      res.end("(403 경계 밖 접근 거절)\n");
      return;
    }
    readFileReply(res, resolved);
    return;
  }

  res.writeHead(404);
  res.end("not found\n");
});

// --- 3. 같은 공격을 양쪽에 보내 결과를 대조한다 -----------------------------
function get(port, pathWithQuery) {
  return new Promise((resolve) => {
    http.get(
      { host: "127.0.0.1", port, path: pathWithQuery },
      (res) => {
        let body = "";
        res.on("data", (c) => (body += c));
        res.on("end", () =>
          resolve({ status: res.statusCode, body: body.trimEnd() }),
        );
      },
    );
  });
}

server.listen(0, "127.0.0.1", async () => {
  const port = server.address().port;
  console.log(process.version);
  console.log(`서버: 127.0.0.1:${port}`);
  console.log(`공개 디렉터리: <tmp>/public  (hello.txt, doc.txt)`);
  console.log(`비밀 파일:     <tmp>/secret.txt  = "TOP-SECRET"`);
  console.log("");

  // hello.txt: 정상 파일
  // ../secret.txt: 상위 디렉터리로 탈출
  // 절대 경로: 비밀 파일의 절대 경로를 그대로 입력
  const attacks = [
    { label: "정상 파일", file: "hello.txt" },
    { label: "상위 탈출", file: "../secret.txt" },
    { label: "절대 경로", file: secretPath },
  ];

  for (const { label, file } of attacks) {
    const q = `?file=${encodeURIComponent(file)}`;
    const vuln = await get(port, `/vuln${q}`);
    const safe = await get(port, `/safe${q}`);
    // 출력에서는 임시 디렉터리 경로를 <tmp>로 가린다(요청에는 실제 절대 경로를 쓴다).
    console.log(`[${label}] file=${String(file).replace(root, "<tmp>")}`);
    console.log(`  /vuln -> ${vuln.status} ${JSON.stringify(vuln.body)}`);
    console.log(`  /safe -> ${safe.status} ${JSON.stringify(safe.body)}`);
    console.log("");
  }

  server.close();
  fs.rmSync(root, { recursive: true, force: true });
});
