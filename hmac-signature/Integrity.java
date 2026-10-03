import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.util.HexFormat;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class Integrity {
    static final HexFormat HEX = HexFormat.of();

    static byte[] sha256(String msg) throws Exception {
        return MessageDigest.getInstance("SHA-256").digest(msg.getBytes(StandardCharsets.UTF_8));
    }

    static byte[] hmac(byte[] key, String msg) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(key, "HmacSHA256"));
        return mac.doFinal(msg.getBytes(StandardCharsets.UTF_8));
    }

    // 받는 쪽이 하는 검증. 받은 메시지로 값을 다시 계산해 받은 값과 비교한다.
    static boolean verifyHash(String msg, byte[] hash) throws Exception {
        return MessageDigest.isEqual(sha256(msg), hash);
    }

    static boolean verifyHmac(byte[] key, String msg, byte[] tag) throws Exception {
        return MessageDigest.isEqual(hmac(key, msg), tag);
    }

    static boolean verifySignature(PublicKey publicKey, String msg, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance("Ed25519");
        sig.initVerify(publicKey);
        sig.update(msg.getBytes(StandardCharsets.UTF_8));
        return sig.verify(signature);
    }

    static byte[] sign(KeyPair keys, String msg) throws Exception {
        Signature sig = Signature.getInstance("Ed25519");
        sig.initSign(keys.getPrivate());
        sig.update(msg.getBytes(StandardCharsets.UTF_8));
        return sig.sign();
    }

    public static void main(String[] args) throws Exception {
        String original = "amount=5000";
        String tampered = "amount=9000";

        System.out.println("== 1. 해시");
        byte[] hash = sha256(original);
        System.out.println("SHA-256(" + original + ") = " + HEX.formatHex(hash));
        System.out.println("원본 메시지 + 원본 해시            -> 통과 " + verifyHash(original, hash));
        System.out.println("바꾼 메시지 + 원본 해시            -> 통과 " + verifyHash(tampered, hash));
        // 공격자는 메시지를 바꾸고 해시도 새로 계산해 함께 보낸다. 키가 필요 없다.
        byte[] hashByAttacker = sha256(tampered);
        System.out.println("바꾼 메시지 + 공격자가 계산한 해시 -> 통과 " + verifyHash(tampered, hashByAttacker));

        System.out.println();
        System.out.println("== 2. HMAC");
        byte[] senderKey = "shared-secret-key".getBytes(StandardCharsets.UTF_8);
        byte[] verifierKey = "shared-secret-key".getBytes(StandardCharsets.UTF_8);   // 같은 키를 나눠 가진다
        byte[] tag = hmac(senderKey, original);
        System.out.println("HMAC(" + original + ") = " + HEX.formatHex(tag));
        System.out.println("원본 메시지 + 원본 태그                 -> 통과 " + verifyHmac(verifierKey, original, tag));
        System.out.println("바꾼 메시지 + 원본 태그                 -> 통과 " + verifyHmac(verifierKey, tampered, tag));
        // 키를 모르는 공격자는 추측한 키로 태그를 만들 수밖에 없다.
        byte[] tagByAttacker = hmac("guessed-key".getBytes(StandardCharsets.UTF_8), tampered);
        System.out.println("바꾼 메시지 + 추측한 키로 만든 태그     -> 통과 " + verifyHmac(verifierKey, tampered, tagByAttacker));
        // 검증하는 쪽은 같은 키를 갖고 있으므로 보낸 쪽과 똑같은 태그를 만들 수 있다.
        System.out.println("보낸 쪽이 만든 태그   " + HEX.formatHex(hmac(senderKey, tampered)));
        System.out.println("검증자가 만든 태그    " + HEX.formatHex(hmac(verifierKey, tampered)));

        System.out.println();
        System.out.println("== 3. 전자서명");
        KeyPair signer = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] signature = sign(signer, original);
        System.out.println("서명 길이 " + signature.length + "바이트");
        System.out.println("원본 메시지 + 서명                     -> 통과 " + verifySignature(signer.getPublic(), original, signature));
        System.out.println("바꾼 메시지 + 서명                     -> 통과 " + verifySignature(signer.getPublic(), tampered, signature));
        // 공격자는 자기 개인키로 서명할 수는 있지만, 검증자는 원래 서명자의 공개키로 검증한다.
        KeyPair attacker = KeyPairGenerator.getInstance("Ed25519").generateKeyPair();
        byte[] signatureByAttacker = sign(attacker, tampered);
        System.out.println("바꾼 메시지 + 공격자 키로 만든 서명    -> 통과 " + verifySignature(signer.getPublic(), tampered, signatureByAttacker));
    }
}
