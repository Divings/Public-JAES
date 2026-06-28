import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;
import java.util.Arrays;

public final class PrivateKeyProtector {

    private static final int SALT_LEN = 16;
    private static final int IV_LEN   = 12;   // GCM推奨
    private static final int TAG_LEN  = 128;  // bits
    private static final int ITER     = 100_000;
    private static final int KEY_LEN  = 256;

    private PrivateKeyProtector() {}

    /* =========================
       保存（暗号化）
       ========================= */
    public static void saveEncrypted(
            PrivateKey privateKey,
            char[] passphrase,
            Path out
    ) throws Exception {

        byte[] salt = random(SALT_LEN);
        byte[] iv   = random(IV_LEN);

        SecretKey aesKey = deriveKey(passphrase, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(TAG_LEN, iv));

        byte[] encrypted = cipher.doFinal(privateKey.getEncoded());

        ByteBuffer buf = ByteBuffer.allocate(
                4 + salt.length +
                4 + iv.length +
                4 + encrypted.length
        );

        buf.putInt(salt.length).put(salt);
        buf.putInt(iv.length).put(iv);
        buf.putInt(encrypted.length).put(encrypted);

        Files.write(out, buf.array());

        zero(passphrase);
    }

    /* =========================
       読み込み（復号）
       ========================= */
    public static PrivateKey loadEncrypted(
            Path in,
            char[] passphrase
    ) throws Exception {

        byte[] all = Files.readAllBytes(in);
        ByteBuffer buf = ByteBuffer.wrap(all);

        byte[] salt = new byte[buf.getInt()];
        buf.get(salt);

        byte[] iv = new byte[buf.getInt()];
        buf.get(iv);

        byte[] encrypted = new byte[buf.getInt()];
        buf.get(encrypted);

        SecretKey aesKey = deriveKey(passphrase, salt);

        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(TAG_LEN, iv));

        byte[] decoded = cipher.doFinal(encrypted);

        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(decoded);
        zero(passphrase);

        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    /* =========================
       内部処理
       ========================= */
    private static SecretKey deriveKey(char[] pass, byte[] salt) throws Exception {
        PBEKeySpec spec = new PBEKeySpec(pass, salt, ITER, KEY_LEN);
        SecretKeyFactory skf =
                SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
        return new SecretKeySpec(skf.generateSecret(spec).getEncoded(), "AES");
    }

    private static byte[] random(int len) {
        byte[] b = new byte[len];
        new SecureRandom().nextBytes(b);
        return b;
    }

    private static void zero(char[] a) {
        if (a != null) Arrays.fill(a, '\0');
    }
}
