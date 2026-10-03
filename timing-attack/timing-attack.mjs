// 타이밍 공격(Timing Attack) PoC
//
// 비밀 값을 "앞에서부터 바이트별로 비교하다 처음 틀린 곳에서 바로 멈추는" 비교로 검사하면,
// 비교에 걸리는 시간이 "앞에서 몇 바이트가 맞았는지"에 비례해 늘어난다.
// 공격자는 이 시간 차이를 측정해 비밀 값을 앞에서부터 한 바이트씩 알아낼 수 있다.
// 방어는 입력이 무엇이든 같은 시간이 걸리는 상수 시간 비교(crypto.timingSafeEqual)다.
//
// 이 파일은 네트워크를 쓰지 않는다. 로컬 함수 두 개의 실행 시간을 직접 측정할 뿐이다.
// 외부로 나가는 요청은 없다.

import crypto from 'node:crypto';

// 16바이트 토큰을 hex로 표현한 32자 문자열. 공격자는 이 값을 모른다고 가정한다.
const SECRET = 'a3f1c0de9b7e4a2f8c1d6e0b5a4f3c2d';
const HEX = '0123456789abcdef';

// 엔진이 inner 루프를 통째로 지워버리지 못하도록 바깥 변수에 결과를 누적한다.
let SINK = 0;

// 취약: 바이트별로 비교하다 처음 틀린 곳에서 바로 return false 한다(조기 반환).
// 일치한 바이트마다 고정된 작은 작업을 한 번 한다. 실제 memcmp도 바이트마다 일정한 일을 하지만
// 그 시간이 타이머 해상도보다 작아 가려지므로, 같은 성질(일치 바이트 수에 비례하는 시간)을
// 측정 가능한 크기로 키운 것이다. 신호의 원리는 바꾸지 않는다.
function vulnEqual(input, secret) {
  if (input.length !== secret.length) return false;
  for (let i = 0; i < secret.length; i++) {
    if (input.charCodeAt(i) !== secret.charCodeAt(i)) return false; // 틀리면 즉시 멈춘다
    let acc = i;
    for (let k = 0; k < 40; k++) acc = (acc * 1103515245 + 12345) & 0x7fffffff;
    SINK += acc;
  }
  return true;
}

// 상수 시간: crypto.timingSafeEqual 은 두 버퍼의 모든 바이트를 끝까지 보며,
// 일치 여부와 무관하게 같은 시간이 걸린다.
// 길이가 다르면 예외를 던지므로 길이를 먼저 확인한다. 다만 길이 분기 자체가 정보가 될 수 있어,
// 실무에서는 두 값을 같은 길이의 해시로 만든 뒤 비교하기도 한다(아래 safeEqualHashed 참고).
function safeEqual(input, secret) {
  const a = Buffer.from(input);
  const b = Buffer.from(secret);
  if (a.length !== b.length) return false;
  return crypto.timingSafeEqual(a, b);
}

// 길이 오라클까지 없애는 변형: 양쪽을 고정 길이 해시로 바꿔 항상 같은 길이로 비교한다.
function safeEqualHashed(input, secret) {
  const a = crypto.createHash('sha256').update(input).digest();
  const b = crypto.createHash('sha256').update(secret).digest();
  return crypto.timingSafeEqual(a, b);
}

// --- 측정 도구 ----------------------------------------------------------------
// process.hrtime.bigint() 로 나노초를 잰다. 한 번의 호출은 너무 짧아 노이즈에 묻히므로
// reps 회 반복한 총 시간을 reps 로 나눠 1회당 평균(ns/op)을 구한다.
function timeOne(fn, input, reps) {
  const t0 = process.hrtime.bigint();
  for (let i = 0; i < reps; i++) fn(input, SECRET);
  const t1 = process.hrtime.bigint();
  return Number(t1 - t0) / reps;
}

function median(arr) {
  const s = [...arr].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : (s[m - 1] + s[m]) / 2;
}

// 비밀과 앞에서 matched 자가 일치하고 그 뒤는 다른, 길이가 같은 후보를 만든다.
function candidate(matched) {
  const prefix = SECRET.slice(0, matched);
  const rest = SECRET.slice(matched).replace(/./g, 'Z'); // 남은 자리는 비밀과 다른 'Z'
  return prefix + rest;
}

// 한 후보를 rounds 라운드로 재고 라운드별 평균의 중앙값을 쓴다.
// 라운드를 나눠 재면 GC나 순간적인 시스템 부하로 생긴 튀는 값을 중앙값이 걸러낸다.
// WARM 라운드는 JIT 워밍업용으로 버린다.
const REPS = Number(process.env.REPS ?? 50000);
const ROUNDS = Number(process.env.ROUNDS ?? 11);
const WARM = 3;

function measure(fn, input) {
  const samples = [];
  for (let r = 0; r < ROUNDS + WARM; r++) {
    const t = timeOne(fn, input, REPS);
    if (r >= WARM) samples.push(t);
  }
  return median(samples);
}

// --- 데모 1: 접두 일치가 늘 때 평균 시간이 어떻게 변하나 -------------------------
function demoTrend() {
  const matches = [0, 8, 16, 24, 32];
  console.log('[데모 1] 접두 일치 바이트 수별 1회 비교 평균 시간 (ns/op)');
  console.log(`         REPS=${REPS} ROUNDS=${ROUNDS} (워밍업 ${WARM}라운드 제외), 라운드별 평균의 중앙값`);
  console.log('');
  console.log('  일치자수 | 취약 vulnEqual | 상수 safeEqual');
  console.log('  ---------+----------------+----------------');
  for (const m of matches) {
    const input = candidate(m);
    const v = measure(vulnEqual, input);
    const s = measure(safeEqual, input);
    console.log(
      `  ${String(m).padStart(6)}   | ${v.toFixed(1).padStart(12)}   | ${s.toFixed(1).padStart(12)}`
    );
  }
  console.log('');
  console.log('  취약: 일치 자 수에 비례해 시간이 는다 → 접두 일치 길이가 샌다.');
  console.log('  상수: 일치 자 수와 무관하게 좁은 구간에 머문다 → 접두 길이가 새지 않는다.');
}

// --- 데모 2: 타이밍만으로 비밀을 앞에서부터 한 자씩 복원 -------------------------
// 각 자리에서 16개 hex 후보를 재고, 가장 느린 후보를 그 자리의 정답으로 택한다.
// 취약한 비교에서는 정답 후보만 한 바이트 더 일치해 한 단위만큼 더 느리다.
//
// 라운드마다 16개 후보를 번갈아 잰다(인터리브). 한 후보를 연속으로 다 재고 다음으로 넘어가면
// CPU 주파수 변화나 순간 부하 같은 느린 드리프트가 특정 후보에만 실려 엉뚱한 자를 고르게 된다.
// 번갈아 재면 그 드리프트가 모든 후보에 고르게 실려 상쇄되므로, 깊은 자리의 작은 신호도 산다.
function recover(fn, reps, rounds) {
  let known = '';
  for (let pos = 0; pos < SECRET.length; pos++) {
    const cands = [...HEX].map((ch) => (known + ch).padEnd(SECRET.length, 'Z'));
    const samples = cands.map(() => []);
    for (let r = 0; r < rounds; r++) {
      for (let c = 0; c < cands.length; c++) samples[c].push(timeOne(fn, cands[c], reps));
    }
    const scores = cands.map((_, c) => median(samples[c]));
    let best = 0;
    for (let c = 1; c < cands.length; c++) if (scores[c] > scores[best]) best = c; // 가장 느린 후보
    known += HEX[best];
  }
  return known;
}

function demoRecover() {
  const reps = Number(process.env.REC_REPS ?? 8000);
  const rounds = Number(process.env.REC_ROUNDS ?? 21);
  console.log('[데모 2] 타이밍만으로 비밀 복원 (각 자리 16개 후보 중 가장 느린 것 선택)');
  console.log(`         REC_REPS=${reps} REC_ROUNDS=${rounds}`);
  console.log('');
  const v = recover(vulnEqual, reps, rounds);
  console.log(`  취약 vulnEqual  복원 결과: ${v}`);
  console.log(`                  비밀과 일치: ${v === SECRET}`);
  const s = recover(safeEqual, reps, rounds);
  console.log(`  상수 safeEqual  복원 결과: ${s}`);
  console.log(`                  비밀과 일치: ${s === SECRET}`);
  console.log(`  실제 비밀값             : ${SECRET}`);
}

console.log(process.version);
console.log(`비밀 토큰(공격자는 모른다고 가정): ${SECRET}`);
// safeEqual / safeEqualHashed 가 실제로 올바른 판정을 하는지 먼저 확인한다.
console.log(`safeEqual(비밀, 비밀) = ${safeEqual(SECRET, SECRET)}, safeEqual('x', 비밀) = ${safeEqual('x', SECRET)}`);
console.log(`safeEqualHashed(비밀, 비밀) = ${safeEqualHashed(SECRET, SECRET)}, safeEqualHashed('x', 비밀) = ${safeEqualHashed('x', SECRET)}`);
console.log('');
demoTrend();
console.log('');
demoRecover();
console.log('');
console.log(`(최적화 방지용 sink: ${SINK % 7})`);
