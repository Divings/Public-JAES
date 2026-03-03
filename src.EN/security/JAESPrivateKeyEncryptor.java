package jaes.crypto;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.KeyGenerator;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.Base64;

/**
 * PEM形式の秘密鍵をAES-GCMで暗号化／復号するユーティリティ。
 * 
 * 暗号化ファイル構造:
 *  [12]  IV
 *  [残り] AES-GCM暗号データ（認証タグ含む）
 */
public final class JAESPrivateKeyEncryptor {

    private static final int AES_KEY_BITS = 256;
    private static final int GCM_TAG_BITS = 128;
    private static final int IV_LEN = 12;

    private JAESPrivateKeyEncryptor() {}

    /** 秘密鍵を暗号化して保存する */
    public static void encryptPrivateKey(Path inputPem, Path outputEnc, char[] password) throws Exception {
        byte[] pemData = Files.readAllBytes(inputPem);
        byte[] keyBytes = deriveAesKey(password); // AESキー導出

        // AES-GCM初期化
        byte[] iv = new byte[IV_LEN];
        new SecureRandom().nextBytes(iv);
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

        byte[] encrypted = cipher.doFinal(pemData);

        // IV + 暗号データを保存
        byte[] out = new byte[IV_LEN + encrypted.length];
        System.arraycopy(iv, 0, out, 0, IV_LEN);
        System.arraycopy(encrypted, 0, out, IV_LEN, encrypted.length);
        Files.write(outputEnc, out, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        System.out.println("秘密鍵を暗号化しました → " + outputEnc);
    }

    /** 暗号化された秘密鍵を復号する */
    public static byte[] decryptPrivateKey(Path encFile, char[] password) throws Exception {
        byte[] all = Files.readAllBytes(encFile);
        if (all.length <= IV_LEN) throw new IllegalArgumentException("ファイルが不正です");

        byte[] iv = new byte[IV_LEN];
        byte[] ciphertext = new byte[all.length - IV_LEN];
        System.arraycopy(all, 0, iv, 0, IV_LEN);
        System.arraycopy(all, IV_LEN, ciphertext, 0, ciphertext.length);

        byte[] keyBytes = deriveAesKey(password);
        SecretKey aesKey = new SecretKeySpec(keyBytes, "AES");
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_BITS, iv));

        return cipher.doFinal(ciphertext);
    }

    /** パスワードからAES鍵を単純導出（PBKDF2などに差し替え可能） */
    private static byte[] deriveAesKey(char[] password) throws Exception {
        // シンプルにSHA-256(password)で導出（※本番はPBKDF2推奨）
        java.security.MessageDigest sha = java.security.MessageDigest.getInstance("SHA-256");
        byte[] passBytes = new String(password).getBytes("UTF-8");
        return sha.digest(passBytes);
    }
}
