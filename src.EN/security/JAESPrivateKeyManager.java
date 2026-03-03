package jaes.crypto;

import java.nio.file.*;
import java.security.PrivateKey;
import java.security.KeyFactory;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Base64;

/**
 * PEM秘密鍵を初回だけ暗号化し、以降は暗号化済みファイルを復号して読み込む。
 */
public final class JAESPrivateKeyManager {

    private static final Path PEM_PATH = KEY_DIR.resolve("private.pem");
    private static final Path ENC_PATH = Paths.get("pri.pem.enc");
    private static final char[] PASSWORD = "MyStrongPass".toCharArray(); // 🔒 実運用では外部設定から

    private JAESPrivateKeyManager() {}

    /** 秘密鍵をロードする（必要なら初回暗号化を実行） */
    public static PrivateKey loadPrivateKey() throws Exception {
        // ① 初回実行: pri.pem が存在 → 暗号化して削除
        if (Files.exists(PEM_PATH) && !Files.exists(ENC_PATH)) {
            System.out.println("初回起動: PEM秘密鍵を検出 → 暗号化します...");
            JAESPrivateKeyEncryptor.encryptPrivateKey(PEM_PATH, ENC_PATH, PASSWORD);
            Files.delete(PEM_PATH);
            System.out.println("秘密鍵を暗号化し、元の PEM ファイルを削除しました。");
        }

        // ② 復号してメモリ上に読み込み
        if (Files.exists(ENC_PATH)) {
            byte[] decrypted = JAESPrivateKeyEncryptor.decryptPrivateKey(ENC_PATH, PASSWORD);
            return parsePemPrivateKey(decrypted);
        } else {
            throw new IllegalStateException("秘密鍵ファイルが見つかりません (pri.pem または pri.pem.enc)");
        }
    }

    /** PEM → PrivateKey に変換 */
    private static PrivateKey parsePemPrivateKey(byte[] pemBytes) throws Exception {
        String pem = new String(pemBytes);
        pem = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(pem);
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(decoded);
        return KeyFactory.getInstance("RSA").generatePrivate(keySpec);
    }
}
