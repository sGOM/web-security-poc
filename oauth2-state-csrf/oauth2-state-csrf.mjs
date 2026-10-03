import http from 'node:http';
import { randomUUID } from 'node:crypto';
import { pathToFileURL } from 'node:url';

// OAuth2 state 파라미터 CSRF(로그인 CSRF / 계정 바인딩) 데모.
//
// 한 프로세스가 작은 인가 서버와 클라이언트를 함께 띄운다. 전부 127.0.0.1.
// 인가 코드 흐름을 메모리로 축약한다.
//   - 클라이언트 /login 이 인가 서버 /authorize 로 보낸다(client_id, redirect_uri, state).
//   - 인가 서버가 로그인된 사용자에게 code 를 발급해 redirect_uri?code=...&state=... 로 되돌린다.
//   - 클라이언트 콜백이 code 를 /token 으로 교환해 그 사용자로 세션을 연다.
//
// 공격은 로그인 CSRF 다. 공격자가 자기 계정의 인가 code 를 미리 얻어,
// 그 code 를 담은 위조 콜백 URL 을 피해자가 열게 만든다.
// 클라이언트가 콜백의 state 를 검증하지 않으면 피해자의 세션이 공격자 계정에 묶인다.
// 핵심 방어는 로그인 시작 때 만든 무작위 state 를 세션에 저장해 두고,
// 콜백의 state 가 그와 일치할 때만 code 를 교환하는 것이다.

// ---- 인가 서버(Authorization Server) 상태 ----
const codes = new Map();          // code -> { user, used }
const REGISTERED_REDIRECTS = new Set([
  '/vuln/callback',
  '/safe/callback',
]);

// ---- 클라이언트(Client) 상태 ----
const clientSessions = new Map(); // sid -> { boundAccount, pendingState }
const accountNotes = new Map();   // 인가 서버 계정 -> [노트]  (클라이언트가 계정별로 쌓는 데이터)

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

async function readBody(req) {
  const chunks = [];
  for await (const c of req) chunks.push(c);
  return Buffer.concat(chunks).toString('utf8');
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  const p = url.pathname;

  // ===== 인가 서버 =====

  // /authorize: 로그인된 사용자(as_user)에게 code 를 발급해 redirect_uri 로 되돌린다.
  // 실제 서버는 as_user 를 인가 서버 자신의 세션 쿠키에서 읽는다. 여기서는 쿼리로 축약한다.
  if (p === '/authorize') {
    const redirectUri = url.searchParams.get('redirect_uri');
    const state = url.searchParams.get('state');
    const asUser = url.searchParams.get('as_user'); // 인가 서버에 로그인된 사용자
    if (!REGISTERED_REDIRECTS.has(redirectUri)) {
      res.writeHead(400).end('unregistered redirect_uri');
      return;
    }
    const code = randomUUID();
    codes.set(code, { user: asUser, used: false });
    const loc = new URL(redirectUri, 'http://127.0.0.1');
    loc.searchParams.set('code', code);
    if (state != null) loc.searchParams.set('state', state); // 받은 state 를 그대로 돌려준다
    res.writeHead(302, { Location: loc.pathname + loc.search }).end();
    return;
  }

  // /token: code 를 사용자 신원으로 교환한다(서버 대 서버). code 는 한 번만 쓴다.
  if (p === '/token' && req.method === 'POST') {
    const form = new URLSearchParams(await readBody(req));
    const rec = codes.get(form.get('code'));
    if (!rec || rec.used) {
      res.writeHead(400, { 'Content-Type': 'application/json' })
        .end(JSON.stringify({ error: 'invalid_grant' }));
      return;
    }
    rec.used = true;
    res.writeHead(200, { 'Content-Type': 'application/json' })
      .end(JSON.stringify({ access_token: randomUUID(), user: rec.user }));
    return;
  }

  // ===== 클라이언트 =====

  // /login?mode=vuln|safe: 세션을 만들고 무작위 state 를 저장한 뒤 인가 서버로 보낸다.
  if (p === '/login') {
    const mode = url.searchParams.get('mode'); // vuln | safe
    const asUser = url.searchParams.get('as_user'); // 데모에서 인가 서버 로그인 사용자를 넘긴다
    let sid = parseCookie(req).sid;
    if (!sid || !clientSessions.has(sid)) {
      sid = randomUUID();
      clientSessions.set(sid, { boundAccount: null, pendingState: null });
    }
    const state = randomUUID();
    clientSessions.get(sid).pendingState = state; // 시작한 요청의 state 를 세션에 보관
    const auth = new URL('/authorize', 'http://127.0.0.1');
    auth.searchParams.set('client_id', 'demo-client');
    auth.searchParams.set('redirect_uri', `/${mode}/callback`);
    auth.searchParams.set('state', state);
    auth.searchParams.set('as_user', asUser);
    res.writeHead(302, {
      'Set-Cookie': `sid=${sid}; HttpOnly; Path=/`,
      Location: auth.pathname + auth.search,
    }).end();
    return;
  }

  // 취약: state 를 검증하지 않고 code 를 그대로 교환해 세션을 연다.
  if (p === '/vuln/callback') {
    const sid = parseCookie(req).sid;
    const sess = clientSessions.get(sid);
    if (!sess) { res.writeHead(401).end('no session'); return; }
    const code = url.searchParams.get('code');
    // state 를 보지 않는다. 들어온 code 를 그대로 교환한다.
    const who = await exchange(code);
    if (!who) { res.writeHead(400).end('exchange failed'); return; }
    sess.boundAccount = who;
    res.writeHead(200, { 'Content-Type': 'application/json' })
      .end(JSON.stringify({ bound: who }));
    return;
  }

  // 고침: 로그인 시작 때 세션에 저장한 state 와 콜백의 state 가 일치할 때만 교환한다.
  if (p === '/safe/callback') {
    const sid = parseCookie(req).sid;
    const sess = clientSessions.get(sid);
    if (!sess) { res.writeHead(401).end('no session'); return; }
    const code = url.searchParams.get('code');
    const state = url.searchParams.get('state');
    if (!state || state !== sess.pendingState) {
      res.writeHead(400, { 'Content-Type': 'application/json' })
        .end(JSON.stringify({ error: 'state mismatch', expected: sess.pendingState, got: state }));
      return;
    }
    sess.pendingState = null; // 1회용
    const who = await exchange(code);
    if (!who) { res.writeHead(400).end('exchange failed'); return; }
    sess.boundAccount = who;
    res.writeHead(200, { 'Content-Type': 'application/json' })
      .end(JSON.stringify({ bound: who }));
    return;
  }

  // /me: 세션이 어느 계정에 묶여 있는지 돌려준다.
  if (p === '/me') {
    const sess = clientSessions.get(parseCookie(req).sid);
    if (!sess || !sess.boundAccount) { res.writeHead(401).end('unauthorized'); return; }
    res.writeHead(200, { 'Content-Type': 'application/json' })
      .end(JSON.stringify({ boundAccount: sess.boundAccount }));
    return;
  }

  // /note: 세션이 묶인 계정 앞으로 데이터를 쌓는다.
  if (p === '/note' && req.method === 'POST') {
    const sess = clientSessions.get(parseCookie(req).sid);
    if (!sess || !sess.boundAccount) { res.writeHead(401).end('unauthorized'); return; }
    const text = (await readBody(req)).trim();
    if (!accountNotes.has(sess.boundAccount)) accountNotes.set(sess.boundAccount, []);
    accountNotes.get(sess.boundAccount).push(text);
    res.writeHead(200).end('saved');
    return;
  }

  res.writeHead(404).end('not found');
});

// 클라이언트가 인가 서버 /token 을 서버 대 서버로 호출해 code 를 신원으로 바꾼다.
async function exchange(code) {
  const base = `http://127.0.0.1:${server.address().port}`;
  const r = await fetch(`${base}/token`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body: new URLSearchParams({ grant_type: 'authorization_code', code: code ?? '' }),
  });
  if (r.status !== 200) return null;
  return (await r.json()).user;
}

async function main() {
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  console.log(process.version);
  console.log(`OAuth2 데모 서버(인가 서버+클라이언트): ${base}`);

  // 리다이렉트를 따라가지 않고 Location 과 Set-Cookie 를 직접 읽는다.
  const h = (sid) => (sid ? { Cookie: `sid=${sid}` } : {});
  const sidOf = (resp) => {
    const m = (resp.headers.get('set-cookie') ?? '').match(/sid=([^;]+)/);
    return m ? m[1] : null;
  };
  const me = async (sid) => {
    const r = await fetch(`${base}/me`, { headers: h(sid), redirect: 'manual' });
    return { status: r.status, body: await r.text() };
  };

  // 인가 서버 로그인 사용자로 한 바퀴 돌려 콜백까지 끌고 간다. (브라우저 리다이렉트를 손으로 따라감)
  async function flow(mode, asUser, sid) {
    const login = await fetch(`${base}/login?mode=${mode}&as_user=${asUser}`, {
      headers: h(sid), redirect: 'manual',
    });
    sid = sidOf(login) ?? sid;
    const authPath = login.headers.get('location'); // /authorize?...
    const authorize = await fetch(`${base}${authPath}`, { redirect: 'manual' });
    const cbPath = authorize.headers.get('location'); // /{mode}/callback?code=&state=
    const cb = await fetch(`${base}${cbPath}`, { headers: h(sid), redirect: 'manual' });
    return { sid, cbPath, cbStatus: cb.status, cbBody: await cb.text() };
  }

  console.log('\n========== 1. 정상 흐름 (state 일치) ==========');
  console.log('피해자 alice 가 자기 계정으로 로그인한다. 양쪽 다 통과해야 한다.');
  const okVuln = await flow('vuln', 'alice', null);
  console.log(`[취약] 콜백 ${okVuln.cbStatus} ${okVuln.cbBody}  -> ${JSON.stringify(await me(okVuln.sid))}`);
  const okSafe = await flow('safe', 'alice', null);
  console.log(`[고침] 콜백 ${okSafe.cbStatus} ${okSafe.cbBody}  -> ${JSON.stringify(await me(okSafe.sid))}`);

  console.log('\n========== 2. 공격자가 자기 계정의 code 를 미리 얻는다 ==========');
  // 공격자가 인가 서버에 자기(attacker) 계정으로 로그인해 콜백 직전까지 간다.
  // /authorize 가 돌려준 Location 에서 자기 code 를 가로채 콜백 URL 을 손에 쥔다.
  async function grabAttackerCallback(mode) {
    const attackerState = 'attacker-chosen-state';
    const authorize = await fetch(
      `${base}/authorize?client_id=demo-client&redirect_uri=/${mode}/callback&state=${attackerState}&as_user=attacker`,
      { redirect: 'manual' },
    );
    return authorize.headers.get('location'); // /{mode}/callback?code=<ATTACKER_CODE>&state=attacker-chosen-state
  }
  const stripState = (cb) => cb.replace(/&state=[^&]*/, ''); // state 없는 위조 콜백
  const forgedVuln = await grabAttackerCallback('vuln');
  const forgedSafe = await grabAttackerCallback('safe');       // 공격자가 정한 state 를 담은 콜백
  const forgedSafeNoState = stripState(await grabAttackerCallback('safe')); // state 를 뺀 콜백
  console.log(`공격자가 쥔 위조 콜백(취약용): ${forgedVuln}`);
  console.log(`공격자가 쥔 위조 콜백(고침용, state 불일치): ${forgedSafe}`);
  console.log(`공격자가 쥔 위조 콜백(고침용, state 없음):   ${forgedSafeNoState}`);

  console.log('\n========== 3. 피해자가 위조 콜백을 연다 ==========');
  console.log('피해자는 이미 자기 계정(alice)으로 로그인된 세션을 들고 있다.');
  console.log(`위조 전 /me: 취약=${(await me(okVuln.sid)).body}, 고침=${(await me(okSafe.sid)).body}`);
  // 로그인을 끝낸 피해자 세션의 저장된 state 를 직접 읽어, 위조 콜백의 state 와 대조한다.
  const storedState = clientSessions.get(okSafe.sid).pendingState;
  const forgedState = new URL(forgedSafe, 'http://127.0.0.1').searchParams.get('state');
  console.log(`피해자 세션에 저장된 state: ${JSON.stringify(storedState)}, 위조 콜백의 state: ${JSON.stringify(forgedState)}, 일치: ${storedState === forgedState}`);

  // 취약: state 를 안 보므로 공격자 code 를 그대로 교환한다.
  const hitVuln = await fetch(`${base}${forgedVuln}`, { headers: h(okVuln.sid), redirect: 'manual' });
  const vulnVerdict = hitVuln.status === 200 ? '수용(세션이 공격자 code 로 재바인딩)' : '거부';
  console.log(`\n[취약] 위조 콜백 응답: ${hitVuln.status} ${await hitVuln.text()}  (${vulnVerdict})`);
  const afterVuln = await me(okVuln.sid);
  console.log(`[취약] 위조 후 /me: ${afterVuln.status} ${afterVuln.body}`);

  // 고침: state 불일치로 거부한다.
  const hitSafe = await fetch(`${base}${forgedSafe}`, { headers: h(okSafe.sid), redirect: 'manual' });
  const safeVerdict = hitSafe.status === 200 ? '수용' : '거부';
  console.log(`\n[고침, state 불일치] 위조 콜백 응답: ${hitSafe.status} ${await hitSafe.text()}  (${safeVerdict})`);
  // 고침: state 가 아예 없어도 거부한다.
  const hitSafeNone = await fetch(`${base}${forgedSafeNoState}`, { headers: h(okSafe.sid), redirect: 'manual' });
  const safeNoneVerdict = hitSafeNone.status === 200 ? '수용' : '거부';
  console.log(`[고침, state 없음]   위조 콜백 응답: ${hitSafeNone.status} ${await hitSafeNone.text()}  (${safeNoneVerdict})`);
  const afterSafe = await me(okSafe.sid);
  console.log(`[고침] 위조 후 /me: ${afterSafe.status} ${afterSafe.body}`);

  // 피해자가 양쪽에서 각각 메모를 올린다. 세션이 묶인 계정 앞으로 쌓인다.
  await fetch(`${base}/note`, { method: 'POST', headers: h(okVuln.sid), body: '취약 세션에서 올린 메모' });
  await fetch(`${base}/note`, { method: 'POST', headers: h(okSafe.sid), body: '고침 세션에서 올린 메모' });

  console.log('\n========== 결과 (측정값) ==========');
  console.log(`취약: 세션이 alice -> ${JSON.parse(afterVuln.body).boundAccount} 로 다시 묶였다.`);
  console.log(`고침: 세션이 ${JSON.parse(afterSafe.body).boundAccount} 그대로다 (위조 콜백 ${hitSafe.status}/${hitSafeNone.status}).`);
  console.log('클라이언트가 계정별로 쌓은 메모(피해자가 올린 것이 누구 계정에 들어갔나):');
  console.log(`  attacker: ${JSON.stringify(accountNotes.get('attacker') ?? [])}`);
  console.log(`  alice:    ${JSON.stringify(accountNotes.get('alice') ?? [])}`);

  server.close();
}

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  main();
}
