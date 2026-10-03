// JWT 서명 검증의 취약점을 보인다. 외부 라이브러리·네트워크 없이 node:crypto만 쓴다.
// 세 검증기를 나란히 둔다:
//   verifyNoSig   : 서명을 검증하지 않고 payload를 그대로 믿는다 (취약: 서명 미검증).
//   verifyAlgTrust: 헤더의 alg를 믿는다. none이면 서명을 안 보고, HS256이면 검증한다 (취약: alg 미고정).
//   verifySafe    : alg를 HS256으로 고정하고, 서명을 검증하고, exp를 본다 (고침).
// 같은 공격 토큰을 세 검증기에 넣어 결과(통과/거부)를 대조한다. now는 재현되도록 고정값을 넘긴다.
import crypto from "node:crypto";

const KEY = Buffer.from("8f2c1e9a4b7d3f60a5c2e8b1d4f7a3c6e9b2d5f8a1c4e7b0d3f6a9c2e5b8d1f4", "hex"); // 32바이트

function b64url(buf) {
  return Buffer.from(buf).toString("base64url");
}

function b64urlJson(obj) {
  return b64url(JSON.stringify(obj));
}

function decodeJson(seg) {
  return JSON.parse(Buffer.from(seg, "base64url").toString());
}

function sign(header, claims, key) {
  const signingInput = b64urlJson(header) + "." + b64urlJson(claims);
  const sig = crypto.createHmac("sha256", key).update(signingInput).digest();
  return signingInput + "." + b64url(sig);
}

// 취약 1: 서명을 검증하지 않는다. payload를 디코딩해 그대로 믿는다. exp도 안 본다.
function verifyNoSig(token) {
  const [, p] = token.split(".");
  return decodeJson(p);
}

// 취약 2: 헤더의 alg를 믿는다. RFC 8725 2.1이 경고하는 형태다.
function verifyAlgTrust(token, key, now) {
  const [h, p] = token.split(".");
  const alg = decodeJson(h).alg;
  if (alg === "none") {
    return decodeJson(p); // 서명을 보지 않고 통과시킨다
  }
  return verifySafe(token, key, now);
}

// 고침: alg 고정 → 서명 검증 → exp 검사 (RFC 7519 7.2, RFC 8725 3.1)
function verifySafe(token, key, now) {
  const [h, p, s] = token.split(".");
  const alg = decodeJson(h).alg;
  if (alg !== "HS256") {
    throw new Error(`허용하지 않는 alg: ${alg}`); // 헤더가 아니라 서버가 alg를 정한다
  }
  const expected = crypto.createHmac("sha256", key).update(`${h}.${p}`).digest();
  const actual = Buffer.from(s ?? "", "base64url");
  if (expected.length !== actual.length || !crypto.timingSafeEqual(expected, actual)) {
    throw new Error("서명 불일치");
  }
  const claims = decodeJson(p);
  if (now >= claims.exp) {
    throw new Error("만료");
  }
  return claims;
}

function attempt(label, fn, token, now) {
  let result;
  try {
    result = `통과 ${JSON.stringify(fn(token, KEY, now))}`;
  } catch (e) {
    result = `거부 (${e.message})`;
  }
  console.log(`  ${label.padEnd(22)} -> ${result}`);
}

// === 1. 발급 ===
const header = { alg: "HS256", typ: "JWT" };
const claims = { sub: "42", role: "user", iat: 1788000000, exp: 1788000900 }; // 15분짜리
const token = sign(header, claims, KEY);
const [h, p, s] = token.split(".");

// 공격 토큰 두 개
const forged = h + "." + b64urlJson({ ...claims, role: "admin" }) + "." + s;        // HS256 헤더, payload만 변조, 옛 서명 유지
const noneToken = b64urlJson({ alg: "none", typ: "JWT" }) + "." + b64urlJson({ ...claims, role: "admin" }) + "."; // alg=none, 서명 비움

const VALID_NOW = 1788000600;   // 발급 10분 뒤
const EXPIRED_NOW = 1788000900; // 발급 15분 뒤 (exp와 같은 순간)

console.log(process.version);
console.log("=== 1. 발급 (HS256) ===");
console.log(token);
console.log();
console.log("=== 2. 공격 토큰 ===");
console.log("payload 변조(role=admin, 옛 서명):", forged);
console.log("alg=none(role=admin, 서명 없음)  :", noneToken);
console.log();
console.log("=== 3. 세 검증기 대조 (now=1788000600, exp=1788000900) ===");
console.log("[A] 원본 토큰");
attempt("취약: 서명 미검증", verifyNoSig, token, VALID_NOW);
attempt("취약: alg 미고정", verifyAlgTrust, token, VALID_NOW);
attempt("고침: verifySafe", verifySafe, token, VALID_NOW);
console.log("[B] payload 변조 (role=admin, HS256, 옛 서명)");
attempt("취약: 서명 미검증", verifyNoSig, forged, VALID_NOW);
attempt("취약: alg 미고정", verifyAlgTrust, forged, VALID_NOW);
attempt("고침: verifySafe", verifySafe, forged, VALID_NOW);
console.log("[C] alg=none (role=admin, 서명 없음)");
attempt("취약: 서명 미검증", verifyNoSig, noneToken, VALID_NOW);
attempt("취약: alg 미고정", verifyAlgTrust, noneToken, VALID_NOW);
attempt("고침: verifySafe", verifySafe, noneToken, VALID_NOW);
console.log("[D] 원본 토큰, 발급 15분 뒤 (now=1788000900, 만료)");
attempt("취약: 서명 미검증", verifyNoSig, token, EXPIRED_NOW);
attempt("취약: alg 미고정", verifyAlgTrust, token, EXPIRED_NOW);
attempt("고침: verifySafe", verifySafe, token, EXPIRED_NOW);
