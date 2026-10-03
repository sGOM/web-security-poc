import http from 'node:http';
import dns from 'node:dns/promises';
import { pathToFileURL } from 'node:url';

// 내부 전용 메타데이터 서버. 외부에 노출되면 안 되는 비밀을 준다.
const internal = http.createServer((req, res) => {
  res.writeHead(200).end(JSON.stringify({ secret: 'INTERNAL-API-KEY-abc123', path: req.url }));
});

// 사용자가 준 url 을 서버가 대신 가져오는 기능(썸네일 생성기 등을 흉내).
async function fetchThrough(targetUrl) {
  const r = await fetch(targetUrl, { redirect: 'manual' });
  return { status: r.status, body: (await r.text()).slice(0, 80) };
}

// 사설 IP 대역인지 본다. 공개 서비스가 요청해선 안 되는 주소들.
function isPrivate(ip) {
  if (ip === '127.0.0.1' || ip === '::1' || ip === '0.0.0.0') return true;
  const p = ip.split('.').map(Number);
  if (p[0] === 10) return true;
  if (p[0] === 172 && p[1] >= 16 && p[1] <= 31) return true;
  if (p[0] === 192 && p[1] === 168) return true;
  if (p[0] === 169 && p[1] === 254) return true;   // 클라우드 메타데이터(169.254.169.254)
  return false;
}

// 호스트 이름을 실제 IP로 풀어서 검사한다. 이름만 보면 DNS로 우회된다.
async function guard(targetUrl) {
  const u = new URL(targetUrl);
  if (u.protocol !== 'http:' && u.protocol !== 'https:') throw new Error(`허용하지 않는 스킴 ${u.protocol}`);
  const { address } = await dns.lookup(u.hostname);
  if (isPrivate(address)) throw new Error(`사설 IP 차단 ${u.hostname} -> ${address}`);
  return address;
}

const proxy = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  const target = url.searchParams.get('url') ?? '';
  const reply = (status, obj) => res.writeHead(status, { 'Content-Type': 'application/json' }).end(JSON.stringify(obj));
  try {
    if (url.pathname === '/vuln/fetch') {
      reply(200, await fetchThrough(target));            // 취약: 검사 없이 가져온다
    } else if (url.pathname === '/safe/check') {
      const ip = await guard(target);                    // 검사만 한다(요청은 보내지 않는다)
      reply(200, { allowed: true, resolved: ip });
    } else reply(404, {});
  } catch (e) {
    reply(400, { error: e.message });
  }
});

if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  await new Promise((r) => internal.listen(0, '127.0.0.1', r));
  await new Promise((r) => proxy.listen(0, '127.0.0.1', r));
  const internalPort = internal.address().port;
  const proxyPort = proxy.address().port;
  console.log('Node.js', process.version);
  console.log(`내부 메타데이터 서버: 127.0.0.1:${internalPort} (외부에 열려선 안 됨)`);

  const call = async (path, target) => {
    const r = await fetch(`http://127.0.0.1:${proxyPort}${path}?url=${encodeURIComponent(target)}`);
    return { status: r.status, body: await r.json() };
  };

  console.log('\n== 1. 취약한 프록시로 내부 서버를 가져온다');
  const victim = `http://127.0.0.1:${internalPort}/secret`;
  console.log(`  대상: ${victim}`);
  const stolen = await call('/vuln/fetch', victim);
  console.log(`  취약 -> ${stolen.status} ${JSON.stringify(stolen.body)}`);

  console.log('\n== 2. 수정본은 가져오기 전에 IP를 분류한다 (요청을 보내지 않는 /safe/check)');
  const targets = [
    'http://93.184.216.34/',                      // 공개 IP (문서용 대역)
    victim,                                        // 루프백
    'http://169.254.169.254/latest/meta-data/',    // 클라우드 메타데이터
    'http://10.0.0.5/',                            // 사설 대역
    'file:///etc/passwd',                          // http가 아닌 스킴
  ];
  for (const target of targets) {
    const c = await call('/safe/check', target);
    const verdict = c.status === 200 ? `허용 (resolved ${c.body.resolved})` : `차단 (${c.body.error})`;
    console.log(`  ${target}\n    -> ${verdict}`);
  }
  internal.close();
  proxy.close();
}
