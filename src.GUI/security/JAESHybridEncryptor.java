package jaes.crypto;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.nio.ByteBuffer;
import java.security.PublicKey;
import java.security.SecureRandom;

/**
 * ハイブリッド暗号 (RSA-OAEP + AES-GCM)
 *
 * 出力バイナリ構造:
 *  [4]  magic: 'J','D','E','C'
 *  [1]  version: 0x01
 *  [2]  ivLen (uint16)
 *  [ivLen]  iv (12推奨)
 *  [2]  wrappedKeyLen (uint16)
 *  [wrappedKeyLen]  rsaWrappedAesKey
 *  [4]  ctLen (uint32)
 *  [ctLen]  ciphertext (GCMタグ込み)
 *
 * 依存: Java標準のみ（BouncyCastle不要）
 */
public final class JAESHybridEncryptor {

    private static final byte[] MAGIC = new byte[]{'J','D','E','C'};
    private static final byte VERSION = 0x01;
    private static final int AES_KEY_BITS = 256;
    private static final int GCM_TAG_BITS = 128; // 16 bytes tag
    private static final int IV_LEN = 12;        // GCM標準

    private JAESHybridEncryptor() {}

    /**
     * 平文をハイブリッド暗号化してJDEC形式のバイト配列を返す。
     * @param plaintext 平文
     * @param rsaPublic 公開鍵（RSA, OAEP-SHA256対応）
     * @param aad 任意の追加認証データ（null可、ヘッダ認証を強めたい場合に使用）
     */
    public static byte[] encrypt(byte[] plaintext, PublicKey rsaPublic, byte[] aad) throws Exception {
        // 1) ランダムAES鍵生成
        SecretKey aesKey = generateAesKey();

        // 2) AES-GCMで本体暗号化
        byte[] iv = new byte[IV_LEN];
        new SecureRandom().nextBytes(iv);

        Cipher gcm = Cipher.getInstance("AES/GCM/NoPadding");
        GCMParameterSpec spec = new GCMParameterSpec(GCM_TAG_BITS, iv);
        gcm.init(Cipher.ENCRYPT_MODE, aesKey, spec);
        if (aad != null && aad.length > 0) {
            gcm.updateAAD(aad);
        }
        byte[] ciphertext = gcm.doFinal(plaintext);

        // 3) RSA-OAEP(SHA-256)でAES鍵をラップ
        Cipher rsa = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
        rsa.init(Cipher.ENCRYPT_MODE, rsaPublic);
        byte[] wrappedKey = rsa.doFinal(aesKey.getEncoded());

        // 4) コンテナ化
        return packJdec(iv, wrappedKey, ciphertext);
    }

    /* ===================== 内部ヘルパ ===================== */

    private static SecretKey generateAesKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_BITS, SecureRandom.getInstanceStrong());
        return kg.generateKey();
    }

    private static byte[] packJdec(byte[] iv, byte[] wrappedKey, byte[] ciphertext) {
        int ivLen = iv.length;
        int wkLen = wrappedKey.length;
        int ctLen = ciphertext.length;

        int total =
                MAGIC.length +         // 4
                1 +                    // version
                2 + ivLen +            // ivLen + iv
                2 + wkLen +            // wrappedKeyLen + wrappedKey
                4 + ctLen;             // ctLen + ciphertext

        ByteBuffer buf = ByteBuffer.allocate(total);
        buf.put(MAGIC);
        buf.put(VERSION);
        buf.putShort((short) ivLen);
        buf.put(iv);
        buf.putShort((short) wkLen);
        buf.put(wrappedKey);
        buf.putInt(ctLen);
        buf.put(ciphertext);
        return buf.array();
    }
}
