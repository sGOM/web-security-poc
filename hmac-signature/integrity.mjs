// 해시 · HMAC · 전자서명이 각각 무엇을 막고 무엇을 못 막는지 비교한다.
// amount=5000 메시지를 공격자가 amount=9000으로 바꾸는 상황을 세 방식에 차례로 보낸다.
// Node.js 24 표준 라이브러리(node:crypto)만 쓴다. 네트워크·외부 라이브러리 없음.
import {
  createHash,
  createHmac,
  generateKeyPairSync,
  sign,
  verify,
  timingSafeEqual,
} from "node:crypto";

const hex = (buf) => buf.toString("hex");

function sha256(msg) {
  return createHash("sha256").update(msg, "utf8").digest();
}

function hmac(key, msg) {
  return createHmac("sha256", key).update(msg, "utf8").digest();
}

// 받는 쪽이 하는 검증. 받은 메시지로 값을 다시 계산해 받은 값과 비교한다.
// timingSafeEqual은 길이가 다르면 예외를 던지므로 길이를 먼저 확인한다.
function verifyHash(msg, hash) {
  const got = sha256(msg);
  return got.length === hash.length && timingSafeEqual(got, hash);
}

function verifyHmac(key, msg, tag) {
  const got = hmac(key, msg);
  return got.length === tag.length && timingSafeEqual(got, tag);
}

function verifySignature(publicKey, msg, signature) {
  return verify(null, Buffer.from(msg, "utf8"), publicKey, signature);
}

function makeSignature(privateKey, msg) {
  return sign(null, Buffer.from(msg, "utf8"), privateKey);
}

const original = "amount=5000";
const tampered = "amount=9000";

console.log("== 1. 해시");
const hash = sha256(original);
console.log(`SHA-256(${original}) = ${hex(hash)}`);
console.log(`원본 메시지 + 원본 해시            -> 통과 ${verifyHash(original, hash)}`);
console.log(`바꾼 메시지 + 원본 해시            -> 통과 ${verifyHash(tampered, hash)}`);
// 공격자는 메시지를 바꾸고 해시도 새로 계산해 함께 보낸다. 키가 필요 없다.
const hashByAttacker = sha256(tampered);
console.log(`바꾼 메시지 + 공격자가 계산한 해시 -> 통과 ${verifyHash(tampered, hashByAttacker)}`);

console.log();
console.log("== 2. HMAC");
const senderKey = Buffer.from("shared-secret-key", "utf8");
const verifierKey = Buffer.from("shared-secret-key", "utf8"); // 같은 키를 나눠 가진다
const tag = hmac(senderKey, original);
console.log(`HMAC(${original}) = ${hex(tag)}`);
console.log(`원본 메시지 + 원본 태그                 -> 통과 ${verifyHmac(verifierKey, original, tag)}`);
console.log(`바꾼 메시지 + 원본 태그                 -> 통과 ${verifyHmac(verifierKey, tampered, tag)}`);
// 키를 모르는 공격자는 추측한 키로 태그를 만들 수밖에 없다.
const tagByAttacker = hmac(Buffer.from("guessed-key", "utf8"), tampered);
console.log(`바꾼 메시지 + 추측한 키로 만든 태그     -> 통과 ${verifyHmac(verifierKey, tampered, tagByAttacker)}`);
// 검증하는 쪽은 같은 키를 갖고 있으므로 보낸 쪽과 똑같은 태그를 만들 수 있다.
console.log(`보낸 쪽이 만든 태그   ${hex(hmac(senderKey, tampered))}`);
console.log(`검증자가 만든 태그    ${hex(hmac(verifierKey, tampered))}`);

console.log();
console.log("== 3. 전자서명");
// 서명 키쌍은 실행마다 새로 만든다. 그래서 서명 값은 매번 달라 찍지 않고 길이와 검증 결과만 찍는다.
const signer = generateKeyPairSync("ed25519");
const signature = makeSignature(signer.privateKey, original);
console.log(`서명 키쌍은 실행마다 새로 생성(서명 값은 매번 달라 찍지 않는다)`);
console.log(`서명 길이 ${signature.length}바이트`);
console.log(`원본 메시지 + 서명                     -> 통과 ${verifySignature(signer.publicKey, original, signature)}`);
console.log(`바꾼 메시지 + 서명                     -> 통과 ${verifySignature(signer.publicKey, tampered, signature)}`);
// 공격자는 자기 개인키로 서명할 수는 있지만, 검증자는 원래 서명자의 공개키로 검증한다.
const attacker = generateKeyPairSync("ed25519");
const signatureByAttacker = makeSignature(attacker.privateKey, tampered);
console.log(`바꾼 메시지 + 공격자 키로 만든 서명    -> 통과 ${verifySignature(signer.publicKey, tampered, signatureByAttacker)}`);
