import http from 'node:http';
import { DatabaseSync } from 'node:sqlite';

const db = new DatabaseSync(':memory:');
db.exec(`
  CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, password TEXT, role TEXT);
  INSERT INTO users VALUES (1, 'alice', 'alice-pw', 'user'), (2, 'admin', 'S3cret!', 'admin');
  CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price INTEGER);
  INSERT INTO products VALUES (1, 'keyboard', 50000), (2, 'mouse', 20000), (3, 'monitor', 300000);
`);

const SORTABLE = new Set(['name', 'price']);       // 정렬에 쓸 수 있는 컬럼의 허용 목록

const handlers = {
  // 취약: 입력을 SQL 문자열에 이어 붙인다.
  '/vuln/login': (q) => {
    const sql = `SELECT name, role FROM users WHERE name = '${q.name}' AND password = '${q.password}'`;
    return { sql, rows: db.prepare(sql).all() };
  },
  // 수정: 값이 들어갈 자리를 ? 로 두고 값은 따로 넘긴다.
  '/safe/login': (q) => {
    const sql = 'SELECT name, role FROM users WHERE name = ? AND password = ?';
    return { sql, rows: db.prepare(sql).all(q.name, q.password) };
  },
  '/vuln/search': (q) => {
    const sql = `SELECT name, price FROM products WHERE name LIKE '%${q.keyword}%'`;
    return { sql, rows: db.prepare(sql).all() };
  },
  '/safe/search': (q) => {
    const sql = "SELECT name, price FROM products WHERE name LIKE '%' || ? || '%'";
    return { sql, rows: db.prepare(sql).all(q.keyword) };
  },
  // 컬럼 이름은 ? 로 넘길 수 없다. 취약한 쪽은 그대로 이어 붙인다.
  '/vuln/list': (q) => {
    const sql = `SELECT name, price FROM products ORDER BY ${q.sort}`;
    return { sql, rows: db.prepare(sql).all() };
  },
  // 수정: 허용 목록에 있는 이름만 받는다.
  '/safe/list': (q) => {
    if (!SORTABLE.has(q.sort)) throw new Error('허용하지 않는 정렬 컬럼');
    const sql = `SELECT name, price FROM products ORDER BY ${q.sort}`;
    return { sql, rows: db.prepare(sql).all() };
  },
};

const server = http.createServer((req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const handler = handlers[url.pathname];
  try {
    const result = handler(Object.fromEntries(url.searchParams));
    res.writeHead(200).end(JSON.stringify(result));
  } catch (e) {
    res.writeHead(400).end(JSON.stringify({ error: e.message }));
  }
});

async function call(port, path, params) {
  const res = await fetch(`http://127.0.0.1:${port}${path}?${new URLSearchParams(params)}`);
  return { status: res.status, ...(await res.json()) };
}

function show(label, r) {
  console.log(`  ${label} -> ${r.status}`);
  if (r.sql) console.log(`    실행된 SQL: ${r.sql}`);
  console.log(`    결과: ${JSON.stringify(r.rows ?? r.error)}`);
}

await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
const port = server.address().port;
console.log('Node.js', process.version);

console.log('\n1. 로그인 우회: 비밀번호를 모르고 admin 으로 로그인한다');
const bypass = { name: "admin' --", password: 'x' };
show('취약', await call(port, '/vuln/login', bypass));
show('수정', await call(port, '/safe/login', bypass));

console.log('\n2. 다른 테이블 읽기: 상품 검색으로 users 테이블을 꺼낸다');
const union = { keyword: "zzz' UNION SELECT name, password FROM users --" };
show('취약', await call(port, '/vuln/search', union));
show('수정', await call(port, '/safe/search', union));

console.log('\n3. 정렬 컬럼: ? 로 바꿀 수 없는 자리');
const guess = (ch) => ({ sort: `(SELECT CASE WHEN (SELECT substr(password, 1, 1) FROM users WHERE name = 'admin') = '${ch}' THEN price ELSE name END)` });
console.log("  첫 글자가 'S'인가 (참이면 가격순, 거짓이면 이름순)");
show("취약, 'S'로 추측", await call(port, '/vuln/list', guess('S')));
show("취약, 'A'로 추측", await call(port, '/vuln/list', guess('A')));
show('수정', await call(port, '/safe/list', guess('S')));
show('수정, 허용된 컬럼', await call(port, '/safe/list', { sort: 'price' }));

server.close();
