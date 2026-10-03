import { chromium } from 'playwright';
import { server } from './xss.mjs';

// 각 경로를 헤드리스 브라우저로 열어, 주입한 스크립트가 실제로 실행됐는지 확인한다.
// 페이로드는 document.title 을 'XSS'로 바꾼다. 제목이 바뀌면 스크립트가 돈 것이다.
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const port = server.address().port;
const payload = `<script>document.title='XSS'</script>`;

const browser = await chromium.launch();
console.log('입력한 댓글:', payload, '\n');

for (const [label, path] of [['취약 (/vuln)', '/vuln'], ['수정 (/safe)', '/safe'], ['CSP (/csp)', '/csp']]) {
  const page = await browser.newPage();
  const violations = [];
  page.on('console', (m) => { if (m.type() === 'error') violations.push(m.text()); });
  await page.goto(`http://127.0.0.1:${port}${path}?comment=${encodeURIComponent(payload)}`);
  const title = await page.title();                 // 스크립트가 돌았으면 'XSS'
  const ran = title === 'XSS';
  console.log(`${label}`);
  console.log(`  스크립트 실행됨: ${ran}`);
  if (violations.length) console.log(`  콘솔 오류: ${violations[0].split('\n')[0]}`);
  await page.close();
}

await browser.close();
server.close();
