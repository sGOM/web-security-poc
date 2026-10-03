import http from 'node:http';
import { pathToFileURL } from 'node:url';

// 사용자가 보낸 comment 를 페이지에 그대로 되비추는 게시판을 흉내 낸다.
// 세 경로는 같은 입력을 다르게 출력한다.
function escapeHtml(s) {
  return s.replace(/[&<>"']/g, (c) =>
    ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
}

function page({ body, csp }) {
  const headers = { 'Content-Type': 'text/html; charset=utf-8' };
  if (csp) headers['Content-Security-Policy'] = "default-src 'self'; script-src 'self'";
  return { headers, html: `<!doctype html><html><body><h1>댓글</h1><div id="comment">${body}</div></body></html>` };
}

export const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://127.0.0.1');
  const comment = url.searchParams.get('comment') ?? '';
  let out;
  if (url.pathname === '/vuln') out = page({ body: comment });                 // 취약: 입력을 그대로 넣는다
  else if (url.pathname === '/safe') out = page({ body: escapeHtml(comment) }); // 수정: HTML로 이스케이프한다
  else if (url.pathname === '/csp') out = page({ body: comment, csp: true });   // 취약하지만 CSP를 건다
  else { res.writeHead(404).end(); return; }
  res.writeHead(200, out.headers).end(out.html);
});

async function render(port, path, comment) {
  const res = await fetch(`http://127.0.0.1:${port}${path}?comment=${encodeURIComponent(comment)}`);
  const html = await res.text();
  const div = html.match(/<div id="comment">(.*)<\/div>/)[1];
  return { csp: res.headers.get('content-security-policy'), div };
}

// 이 파일을 직접 실행했을 때만 데모를 돈다(체커가 import 할 때는 안 돈다).
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  const payload = `<script>document.title='XSS'</script>`;
  console.log('Node.js', process.version);
  console.log('입력한 댓글:', payload, '\n');
  for (const [label, path] of [['취약 (/vuln)', '/vuln'], ['수정 (/safe)', '/safe'], ['CSP (/csp)', '/csp']]) {
    const r = await render(port, path, payload);
    console.log(`${label}`);
    console.log(`  #comment 안의 HTML: ${r.div}`);
    console.log(`  CSP 헤더: ${r.csp ?? '(없음)'}`);
    console.log();
  }
  server.close();
}
