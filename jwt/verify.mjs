// jwt_demo.py가 발급한 토큰을 Node.js 표준 crypto로 검증한다.
import crypto from "node:crypto";

const key = Buffer.from("8f2c1e9a4b7d3f60a5c2e8b1d4f7a3c6e9b2d5f8a1c4e7b0d3f6a9c2e5b8d1f4", "hex");
const [h, p, s] = process.argv[2].split(".");
const expected = crypto.createHmac("sha256", key).update(`${h}.${p}`).digest("base64url");

console.log("서명 일치:", crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(s)));
console.log("payload:", JSON.parse(Buffer.from(p, "base64url").toString()));
