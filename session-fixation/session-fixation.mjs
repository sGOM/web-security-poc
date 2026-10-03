import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';

// 세션 고정(Session Fixation) 데모.
// 인메모리 세션 저장소에 sessionId -> { user } 를 담는다.
// 로그인 전부터 존재하던 세션 ID 를 로그인 뒤에도 그대로 쓰면,
// 공격자가 미리 심어 둔 세션 ID 로 피해자의 로그인 세션을 가로챈다.
// 핵심 방어는 로그인 성공 시 세션 ID 를 새로 발급(regenerate)하는 것이다.

const sessions = new Map(); // sessionId -> { user }

const USER = 'victim';
const PASS = 'correct horse battery staple';

function parseCookie(req) {
  const raw = req.headers.cookie ?? '';
  const out = {};
  for (const part of raw.split(';')) {
    const i = part.indexOf('=');
    if (i < 0) continue;
    out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

async function readJson(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  if (chunks.length === 0) return {};
  try {
    return JSON.parse(Buffer.concat(chunks).toString('utf8'));
  } catch {
    return {};
  }
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  const sid = parseCookie(req).sid;

  if (req.method === 'POST' && url.pathname === '/vuln/login') {
    const { user, pass } = await readJson(req);
    if (user !== USER || pass !== PASS) {
      res.writeHead(401).end('bad credentials');
      return;
    }
    // 취약: 들어온 세션 ID 를 그대로 두고 그 세션에 user 를 붙인다.
    // 로그인 전부터 쓰던 ID 가 그대로 로그인된 세션이 된다.
    sessions.set(sid, { user });
    res.writeHead(200, { 'Set-Cookie': `sid=${sid}; HttpOnly; Path=/` }).end('ok');
    return;
  }

  if (req.method === 'POST' && url.pathname === '/safe/login') {
    const { user, pass } = await readJson(req);
    if (user !== USER || pass !== PASS) {
      res.writeHead(401).end('bad credentials');
      return;
    }
    // 고침: 로그인 성공 시 세션 ID 를 새로 발급하고 옛 세션은 버린다.
    sessions.delete(sid);                 // 로그인 전 세션 폐기
    const newSid = randomUUID();          // 새 세션 ID
    sessions.set(newSid, { user });
    res.writeHead(200, { 'Set-Cookie': `sid=${newSid}; HttpOnly; Path=/` }).end('ok');
    return;
  }

  if (req.method === 'GET' && url.pathname === '/me') {
    // 보호된 페이지: 세션에 user 가 있어야 본다.
    const session = sessions.get(sid);
    if (!session) {
      res.writeHead(401, { 'Content-Type': 'application/json' }).end(JSON.stringify({ error: 'unauthorized' }));
      return;
    }
    res.writeHead(200, { 'Content-Type': 'application/json' }).end(JSON.stringify({ user: session.user }));
    return;
  }

  res.writeHead(404).end();
});

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;
  console.log('Node.js', process.version);
  console.log(`세션 서버: ${base}`);

  const FIXED = 'ATTACKER-FIXED-SID';

  // 피해자가 특정 세션 ID 를 쿠키로 들고 로그인한다.
  const login = (path, sidCookie) =>
    fetch(`${base}${path}`, {
      method: 'POST',
      redirect: 'manual',
      headers: { 'Content-Type': 'application/json', Cookie: `sid=${sidCookie}` },
      body: JSON.stringify({ user: USER, pass: PASS }),
    });

  // 공격자가 특정 세션 ID 로 /me 를 본다.
  const me = async (sidCookie) => {
    const r = await fetch(`${base}/me`, { headers: { Cookie: `sid=${sidCookie}` } });
    const body = await r.text();
    return { status: r.status, body };
  };

  // Set-Cookie 에서 새 sid 값을 뽑는다.
  const sidFromSetCookie = (resp) => {
    const sc = resp.headers.get('set-cookie') ?? '';
    const m = sc.match(/sid=([^;]+)/);
    return m ? m[1] : null;
  };

  async function run(label, loginPath) {
    console.log(`\n=== ${label}: ${loginPath} ===`);
    console.log(`1. 공격자가 고정 세션 ID 를 정한다: sid=${FIXED}`);
    console.log('2. 피해자가 그 세션 ID 를 쿠키로 들고 로그인한다');
    const loginResp = await login(loginPath, FIXED);
    const issued = sidFromSetCookie(loginResp);
    console.log(`   로그인 응답: ${loginResp.status}, 발급된 sid: ${issued}`);
    console.log(`   들어온 ID 와 같은가: ${issued === FIXED}`);
    console.log(`3. 공격자가 쥔 ${FIXED} 로 /me 를 요청한다`);
    const seen = await me(FIXED);
    const verdict = seen.status === 200 ? '가로채기 성공' : '가로채기 실패';
    console.log(`   -> ${seen.status} ${seen.body}  (${verdict})`);
    return { issued, meStatus: seen.status };
  }

  const vuln = await run('취약', '/vuln/login');
  const safe = await run('고침', '/safe/login');

  console.log('\n--- 요약 ---');
  console.log(`취약: 발급 sid=${vuln.issued} (고정 ID 그대로), 공격자 /me -> ${vuln.meStatus}`);
  console.log(`고침: 발급 sid=${safe.issued} (새 ID, 고정 ID와 다름), 공격자 /me -> ${safe.meStatus}`);

  server.close();
}
