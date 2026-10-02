import http from 'node:http';
import crypto from 'node:crypto';

const sessions = new Map();      // 세션 ID -> { balance, csrfToken }

function sessionOf(req) {
  const id = /session=([^;]+)/.exec(req.headers.cookie ?? '')?.[1];
  return sessions.get(id);
}

const server = http.createServer((req, res) => {
  const reply = (status, body) => res.writeHead(status).end(body);

  if (req.url === '/login') {
    const id = crypto.randomUUID();
    const csrfToken = crypto.randomUUID();
    sessions.set(id, { balance: 10000, csrfToken });
    // SameSite=None: 다른 사이트에서 시작된 요청에도 실리도록 설정한 쿠키다.
    res.writeHead(200, { 'Set-Cookie': `session=${id}; HttpOnly; Secure; SameSite=None` }).end(csrfToken);
    return;
  }

  const session = sessionOf(req);
  if (!session) return reply(401, '로그인 필요');
  const self = `http://${req.headers.host}`;

  // 방어 없음: 세션 쿠키만 본다.
  if (req.url === '/transfer/none') {
    session.balance -= 1000;
    return reply(200, `이체 완료, 잔액 ${session.balance}`);
  }
  // 토큰 확인: 쿠키와 별개로, 페이지에 내려 준 값을 헤더로 받아 대조한다.
  if (req.url === '/transfer/token') {
    if (req.headers['x-csrf-token'] !== session.csrfToken) return reply(403, 'CSRF 토큰 불일치');
    session.balance -= 1000;
    return reply(200, `이체 완료, 잔액 ${session.balance}`);
  }
  // 출처 확인: Origin 헤더가 이 서버의 출처와 같은지 본다.
  if (req.url === '/transfer/origin') {
    if (req.headers.origin !== self) return reply(403, `허용하지 않는 출처 ${req.headers.origin}`);
    session.balance -= 1000;
    return reply(200, `이체 완료, 잔액 ${session.balance}`);
  }
  reply(404, '없음');
});

function post(port, path, headers) {
  return new Promise((resolve) => {
    const req = http.request({ port, path, method: 'POST', headers }, (res) => {
      let body = '';
      res.on('data', (chunk) => (body += chunk));
      res.on('end', () => resolve({ status: res.statusCode, body, cookie: res.headers['set-cookie']?.[0] }));
    });
    req.end();
  });
}

await new Promise((resolve) => server.listen(0, resolve));
const port = server.address().port;
const self = `http://localhost:${port}`;

const login = await post(port, '/login', {});
const cookie = login.cookie.split(';')[0];     // 브라우저가 보관하는 세션 쿠키
const token = login.body;                      // 은행 페이지의 스크립트만 읽을 수 있는 값

// 은행 페이지에서 보낸 요청: 쿠키, 자기 출처, 토큰이 모두 실린다.
const fromBank = { Cookie: cookie, Origin: self, 'X-CSRF-Token': token };
// 공격자 페이지가 만든 요청: 쿠키는 브라우저가 붙여 준다. 출처는 공격자 것이고 토큰은 모른다.
const fromAttacker = { Cookie: cookie, Origin: 'https://evil.example' };

console.log('Node.js', process.version);
for (const path of ['/transfer/none', '/transfer/token', '/transfer/origin']) {
  console.log(`\n${path}`);
  for (const [who, headers] of [['은행 페이지  ', fromBank], ['공격자 페이지', fromAttacker]]) {
    const r = await post(port, path, headers);
    console.log(`  ${who} -> ${r.status} ${r.body}`);
  }
}
server.close();
