# SQL 인젝션 (SQL Injection)

사용자 입력을 SQL 문자열에 그대로 이어 붙이면, 입력의 일부가 데이터가 아니라 명령으로 실행된다. 공격자는 비밀번호를 모르고 로그인하거나, 다른 테이블의 내용을 꺼내거나, 한 글자씩 비밀 값을 알아낸다.

글: [SQL 인젝션 — 문자열로 이어 붙인 쿼리가 명령이 되는 과정](https://sgom.github.io/posts/sql-injection/)

## 무엇을 보이나

같은 공격을 취약한 주소와 고친 주소에 보낸다. 취약한 쪽은 입력을 SQL에 이어 붙이고, 고친 쪽은 값을 `?` 자리로 분리하거나(바인딩) 허용 목록으로 거른다.

| 공격 | 취약 | 수정 |
|---|---|---|
| 로그인 우회 (`admin' --`) | 비밀번호 없이 admin 로그인 | 바인딩, 일치하는 행 없음 |
| UNION으로 다른 테이블 읽기 | `users`의 비밀번호가 상품 검색 결과에 섞여 나옴 | 바인딩, 결과 없음 |
| 정렬 컬럼 (`?`로 못 바꾸는 자리) | `ORDER BY` 식으로 비밀 값을 한 글자씩 추론 | 허용 목록에 없는 컬럼은 400 |

셋째 공격은 값이 아니라 컬럼 이름이 들어가는 자리다. 이 자리는 `?` 바인딩으로 바꿀 수 없어, 허용 목록으로 막는 것을 함께 보인다.

## 실행

Node.js 24. 내장 `node:sqlite`를 쓰고 의존성이 없다.

```sh
node sqli.mjs
```

```
Node.js v24.15.0

1. 로그인 우회: 비밀번호를 모르고 admin 으로 로그인한다
  취약 -> 200
    실행된 SQL: SELECT name, role FROM users WHERE name = 'admin' --' AND password = 'x'
    결과: [{"name":"admin","role":"admin"}]
  수정 -> 200
    실행된 SQL: SELECT name, role FROM users WHERE name = ? AND password = ?
    결과: []

2. 다른 테이블 읽기: 상품 검색으로 users 테이블을 꺼낸다
  취약 -> 200
    실행된 SQL: SELECT name, price FROM products WHERE name LIKE '%zzz' UNION SELECT name, password FROM users --%'
    결과: [{"name":"admin","price":"S3cret!"},{"name":"alice","price":"alice-pw"}]
  수정 -> 200
    실행된 SQL: SELECT name, price FROM products WHERE name LIKE '%' || ? || '%'
    결과: []

3. 정렬 컬럼: ? 로 바꿀 수 없는 자리
  첫 글자가 'S'인가 (참이면 가격순, 거짓이면 이름순)
  취약, 'S'로 추측 -> 200
    실행된 SQL: SELECT name, price FROM products ORDER BY (SELECT CASE WHEN (SELECT substr(password, 1, 1) FROM users WHERE name = 'admin') = 'S' THEN price ELSE name END)
    결과: [{"name":"mouse","price":20000},{"name":"keyboard","price":50000},{"name":"monitor","price":300000}]
  취약, 'A'로 추측 -> 200
    실행된 SQL: SELECT name, price FROM products ORDER BY (SELECT CASE WHEN (SELECT substr(password, 1, 1) FROM users WHERE name = 'admin') = 'A' THEN price ELSE name END)
    결과: [{"name":"keyboard","price":50000},{"name":"monitor","price":300000},{"name":"mouse","price":20000}]
  수정 -> 400
    결과: "허용하지 않는 정렬 컬럼"
  수정, 허용된 컬럼 -> 200
    실행된 SQL: SELECT name, price FROM products ORDER BY price
    결과: [{"name":"mouse","price":20000},{"name":"keyboard","price":50000},{"name":"monitor","price":300000}]
```

## 읽는 법

- 취약한 쪽의 "실행된 SQL" 줄을 보면 입력이 SQL 구조를 바꾼 것이 드러난다. `admin' --`의 `--`가 뒤의 비밀번호 조건을 주석으로 지운다.
- 수정한 쪽은 "실행된 SQL"에 `?`가 그대로 남아 있다. 입력은 값으로만 들어가 구조를 바꾸지 못한다.
- 셋째 공격의 취약한 쪽은 오류 없이 200을 돌려준다. 정렬 순서가 바뀌는 것만으로 비밀 값의 첫 글자가 `S`인지를 알 수 있다(블라인드 인젝션).

## 한계

SQLite 인메모리 DB다. DBMS마다 주석 기호와 문자열 이어 붙이기 문법이 조금씩 다르지만, 입력이 명령이 되는 구조와 바인딩이 그것을 막는 원리는 같다. 실제 공격은 더 많은 단계를 거치는데, 여기서는 구조가 드러나는 최소 형태만 보인다.

## 파일

- `sqli.mjs`: 서버와 세 공격을 한 파일에 담았다. 서버는 `127.0.0.1`의 임의 포트에 뜨고 실행이 끝나면 닫힌다.
