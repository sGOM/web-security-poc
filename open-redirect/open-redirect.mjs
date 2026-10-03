import http from 'node:http';
import { pathToFileURL } from 'node:url';

// 로그인 뒤 ?next= 로 받은 주소로 돌려보내는 흐름을 흉내낸다.
// 실제 로그인은 생략하고, next 값을 어디로 보낼지 결정하는 부분만 보인다.

// 안전한 판정: "같은 사이트 내부 경로"만 허용한다. 그 밖은 기본 경로('/')로 돌린다.
//  1) 반드시 슬래시 하나로 시작해야 하고, '//' 나 '/\' 로 시작하면 안 된다.
//     (스킴 상대 URL과 역슬래시 우회를 파서에 기대지 않고 먼저 걷어낸다)
//  2) base 를 기준으로 파싱한 origin 이 서버 자신과 같아야 한다.
function safeNext(next, base) {
  if (typeof next !== 'string') return '/';
  if (!next.startsWith('/') || next.startsWith('//') || next.startsWith('/\\')) return '/';
  let resolved;
  try {
    resolved = new URL(next, base);
  } catch {
    return '/';
  }
  if (resolved.origin !== base) return '/';
  return next;
}

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  const next = url.searchParams.get('next') ?? '';

  if (url.pathname === '/vuln/redirect') {
    // 취약: next 값을 검증 없이 그대로 Location 에 넣는다.
    res.writeHead(302, { Location: next }).end();
  } else if (url.pathname === '/safe/redirect') {
    // 고침: 내부 경로만 허용하고, 그 밖은 '/' 로 돌린다.
    const base = `http://127.0.0.1:${server.address().port}`;
    res.writeHead(302, { Location: safeNext(next, base) }).end();
  } else {
    res.writeHead(404).end();
  }
});

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const base = `http://127.0.0.1:${port}`;
  console.log('Node.js', process.version);
  console.log(`로그인 서버: ${base}`);

  // redirect:'manual' 로 302 를 따라가지 않고 Location 헤더만 읽는다.
  const locationOf = async (path, next) => {
    const r = await fetch(`${base}${path}?next=${encodeURIComponent(next)}`, { redirect: 'manual' });
    return { status: r.status, location: r.headers.get('location') };
  };

  const inputs = [
    '/dashboard',                      // 정상 내부 경로
    'https://evil.example/phish',      // 외부 절대 URL
    '//evil.example',                  // 스킴 상대 URL
    '/' + String.fromCharCode(92) + 'evil.example',  // 백슬래시 우회 (/\evil.example)
    'javascript:alert(1)',             // javascript: 스킴
  ];

  console.log('\nnext 값마다 취약/고침의 Location(302) 을 대조한다.');
  for (const next of inputs) {
    const v = await locationOf('/vuln/redirect', next);
    const s = await locationOf('/safe/redirect', next);
    const verdict = s.location === next ? '허용' : `거절 -> ${s.location}`;
    console.log(`\n  next = ${JSON.stringify(next)}`);
    console.log(`    취약 /vuln/redirect -> ${v.status} Location: ${v.location}`);
    console.log(`    고침 /safe/redirect -> ${s.status} ${verdict}`);
  }

  server.close();
}
