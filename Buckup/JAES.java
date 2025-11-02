import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.time.Instant;
import java.util.*;

/**
 * JAES.java - Interactive Hybrid AES-GCM + RSA-OAEP Encryption Tool
 * Java 8 compatible / UTF-8 safe
 */
public class JAES {

    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_NONCE_LEN = 12;
    private static final int GCM_TAG_LEN = 16;
    private static final String OAEP_TRANSFORM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String BLOCKCHAIN_HEADER_STR = "BLOCKCHAIN_DATA_START\n";
    private static final byte[] BLOCKCHAIN_HEADER = BLOCKCHAIN_HEADER_STR.getBytes(StandardCharsets.UTF_8);

    private static final Path KEY_DIR = Paths.get("key");
    private static final Path PRIV_PEM = KEY_DIR.resolve("private.pem");
    private static final Path PUB_PEM = KEY_DIR.resolve("public.pem");

    public static void main(String[] args) {
        System.out.println("🔒 JAES Hybrid Encryption Tool (Interactive Edition)");
        System.out.println("--------------------------------------------------");

        try {
            Files.createDirectories(KEY_DIR);
            ensureKeyPair();
        } catch (Exception e) {
            System.err.println("鍵ディレクトリ作成に失敗しました: " + e.getMessage());
            return;
        }

        Scanner sc = new Scanner(System.in, "UTF-8");

        while (true) {
            System.out.println();
            System.out.println("モードを選択してください:");
            System.out.println("1: 暗号化");
            System.out.println("2: 復号化");
            System.out.println("3: ブロックチェーン検証");
            System.out.println("4: 終了");
            System.out.print("選択 >> ");
            String choice = sc.nextLine().trim();

            try {
                if ("1".equals(choice)) {
                    System.out.print("暗号化するファイルのパスを入力: ");
                    Path input = Paths.get(sc.nextLine().trim());
                    if (!Files.exists(input)) {
                        System.out.println("❌ ファイルが存在しません。");
                        continue;
                    }
                    System.out.print("メモ（任意）: ");
                    String memo = sc.nextLine();
                    encryptFileHybrid(input, input.resolveSibling(input.getFileName() + ".jdec"), PUB_PEM, memo);
                    System.out.println("✅ 暗号化完了: " + input.getFileName() + ".jdec");
                } else if ("2".equals(choice)) {
                    System.out.print("復号するファイルのパスを入力: ");
                    Path input = Paths.get(sc.nextLine().trim());
                    if (!Files.exists(input)) {
                        System.out.println("❌ ファイルが存在しません。");
                        continue;
                    }
                    System.out.print("メモ（任意）: ");
                    String memo = sc.nextLine();
                    Path output = guessDecryptedName(input);
                    decryptFileHybrid(input, output, PRIV_PEM, memo);
                    System.out.println("✅ 復号完了: " + output.getFileName());
                } else if ("3".equals(choice)) {
                    System.out.print("検証するファイルのパスを入力: ");
                    Path input = Paths.get(sc.nextLine().trim());
                    if (!Files.exists(input)) {
                        System.out.println("❌ ファイルが存在しません。");
                        continue;
                    }
                    Optional<String> chainJson = readBlockchainJsonIfAny(Files.readAllBytes(input));
                    if (!chainJson.isPresent()) {
                        System.out.println("ℹ ブロックチェーンデータが見つかりません。");
                    } else {
                        Blockchain chain = Blockchain.fromJson(chainJson.get());
                        boolean ok = chain.isValid();
                        System.out.println(ok ? "✅ チェーンは整合しています。" : "❌ チェーンが改ざんされています。");
                    }
                } else if ("4".equals(choice)) {
                    System.out.println("👋 終了します。");
                    break;
                } else {
                    System.out.println("❌ 無効な選択です。");
                }
            } catch (Exception e) {
                System.err.println("⚠ エラー: " + e.getMessage());
            }
        }
    }

    // ===== Utility =====
    private static Path guessDecryptedName(Path input) {
        String name = input.getFileName().toString();
        if (name.endsWith(".jdec")) {
            return input.getParent() == null ?
                    Paths.get(name.substring(0, name.length() - 5)) :
                    input.getParent().resolve(name.substring(0, name.length() - 5));
        }
        return input.resolveSibling(name + ".dec");
    }

    private static Optional<String> readBlockchainJsonIfAny(byte[] data) {
        int split = indexOf(data, BLOCKCHAIN_HEADER);
        if (split < 0) return Optional.empty();
        String json = new String(Arrays.copyOfRange(data, split + BLOCKCHAIN_HEADER.length, data.length), StandardCharsets.UTF_8);
        return Optional.of(json);
    }

    private static void ensureKeyPair() throws Exception {
        if (Files.exists(PRIV_PEM) && Files.exists(PUB_PEM)) return;

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        writePem("PRIVATE KEY", kp.getPrivate().getEncoded(), PRIV_PEM);
        writePem("PUBLIC KEY", kp.getPublic().getEncoded(), PUB_PEM);
        System.out.println("[INFO] RSA鍵ペアを生成しました (./key)");
    }

    private static void writePem(String type, byte[] der, Path out) throws IOException {
        String b64 = Base64.getEncoder().encodeToString(der);
        BufferedWriter w = Files.newBufferedWriter(out, StandardCharsets.US_ASCII);
        w.write("-----BEGIN " + type + "-----\n");
        for (int i = 0; i < b64.length(); i += 64)
            w.write(b64.substring(i, Math.min(i + 64, b64.length())) + "\n");
        w.write("-----END " + type + "-----\n");
        w.close();
    }

    // ===== Encryption / Decryption =====
    private static void encryptFileHybrid(Path input, Path output, Path publicPem, String memo) throws Exception {
        byte[] plaintext = Files.readAllBytes(input);

        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_SIZE);
        SecretKey aesKey = kg.generateKey();

        byte[] nonce = new byte[GCM_NONCE_LEN];
        SecureRandom sr = new SecureRandom();
        sr.nextBytes(nonce);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LEN * 8, nonce));
        byte[] cipherAll = aes.doFinal(plaintext);

        int ctLen = cipherAll.length - GCM_TAG_LEN;
        byte[] ciphertext = Arrays.copyOfRange(cipherAll, 0, ctLen);
        byte[] tag = Arrays.copyOfRange(cipherAll, ctLen, cipherAll.length);

        PublicKey pub = loadPublicKeyFromPemOrDer(publicPem);
        Cipher rsa = Cipher.getInstance(OAEP_TRANSFORM);
        rsa.init(Cipher.ENCRYPT_MODE, pub);
        byte[] encKey = rsa.doFinal(aesKey.getEncoded());

        ByteBuffer header = ByteBuffer.allocate(4 + encKey.length + nonce.length + ciphertext.length + tag.length);
        header.putInt(encKey.length);
        header.put(encKey);
        header.put(nonce);
        header.put(ciphertext);
        header.put(tag);

        Blockchain chain = new Blockchain();
        String user = System.getProperty("user.name", "unknown");
        String fileHash = sha256Hex(ciphertext);
        chain.addBlock(new Block(fileHash, "Encrypt", user, memo));

        OutputStream os = Files.newOutputStream(output, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        os.write(header.array());
        os.write(BLOCKCHAIN_HEADER);
        os.write(chain.toJson().getBytes(StandardCharsets.UTF_8));
        os.close();
    }

    private static void decryptFileHybrid(Path input, Path output, Path privatePem, String memo) throws Exception {
        byte[] blob = Files.readAllBytes(input);

        int split = indexOf(blob, BLOCKCHAIN_HEADER);
        byte[] cryptoPart;
        String existingChainJson = null;
        if (split >= 0) {
            cryptoPart = Arrays.copyOfRange(blob, 0, split);
            existingChainJson = new String(Arrays.copyOfRange(blob, split + BLOCKCHAIN_HEADER.length, blob.length), StandardCharsets.UTF_8);
        } else {
            cryptoPart = blob;
        }

        ByteBuffer buf = ByteBuffer.wrap(cryptoPart);
        int keyLen = buf.getInt();
        byte[] encKey = new byte[keyLen];
        buf.get(encKey);
        byte[] nonce = new byte[GCM_NONCE_LEN];
        buf.get(nonce);

        int remain = buf.remaining();
        byte[] ciphertext = new byte[remain - GCM_TAG_LEN];
        buf.get(ciphertext);
        byte[] tag = new byte[GCM_TAG_LEN];
        buf.get(tag);

        PrivateKey priv = loadPrivateKeyFromPemOrDer(privatePem);
        Cipher rsa = Cipher.getInstance(OAEP_TRANSFORM);
        rsa.init(Cipher.DECRYPT_MODE, priv);
        byte[] aesKeyBytes = rsa.doFinal(encKey);

        SecretKey aesKey = new javax.crypto.spec.SecretKeySpec(aesKeyBytes, "AES");
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LEN * 8, nonce));

        byte[] cipherAll = new byte[ciphertext.length + tag.length];
        System.arraycopy(ciphertext, 0, cipherAll, 0, ciphertext.length);
        System.arraycopy(tag, 0, cipherAll, ciphertext.length, tag.length);

        byte[] plaintext = aes.doFinal(cipherAll);
        Files.write(output, plaintext, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        Blockchain chain = (existingChainJson != null && !existingChainJson.trim().isEmpty())
                ? Blockchain.fromJson(existingChainJson)
                : new Blockchain();

        String user = System.getProperty("user.name", "unknown");
        String fileHash = sha256Hex(ciphertext);
        chain.addBlock(new Block(fileHash, "Decrypt", user, memo));

        OutputStream os = Files.newOutputStream(input, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        os.write(cryptoPart);
        os.write(BLOCKCHAIN_HEADER);
        os.write(chain.toJson().getBytes(StandardCharsets.UTF_8));
        os.close();
    }

    private static int indexOf(byte[] data, byte[] pattern) {
        for (int i = 0; i <= data.length - pattern.length; i++) {
            boolean match = true;
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    match = false;
                    break;
                }
            }
            if (match) return i;
        }
        return -1;
    }

    private static String sha256Hex(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] h = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (byte b : h) sb.append(String.format("%02x", b));
        return sb.toString();
    }

    private static PublicKey loadPublicKeyFromPemOrDer(Path p) throws Exception {
        byte[] all = Files.readAllBytes(p);
        byte[] der = tryExtractDerFromPem(all, "PUBLIC KEY");
        if (der == null) der = all;
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private static PrivateKey loadPrivateKeyFromPemOrDer(Path p) throws Exception {
        byte[] all = Files.readAllBytes(p);
        byte[] der = tryExtractDerFromPem(all, "PRIVATE KEY");
        if (der == null) der = all;
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(der);
        return KeyFactory.getInstance("RSA").generatePrivate(spec);
    }

    private static byte[] tryExtractDerFromPem(byte[] pemBytes, String type) {
        String s = new String(pemBytes, StandardCharsets.US_ASCII);
        String head = "-----BEGIN " + type + "-----";
        String foot = "-----END " + type + "-----";
        int i = s.indexOf(head);
        int j = s.indexOf(foot);
        if (i < 0 || j < 0) return null;
        String b64 = s.substring(i + head.length(), j).replaceAll("\\s", "");
        return Base64.getDecoder().decode(b64);
    }

    // ===== Blockchain classes =====
    static class Block {
        public String timestamp;
        public String previousHash;
        public String operationType;
        public String fileHash;
        public String user;
        public String memo;
        public String hash;

        Block(String fileHash, String operationType, String user, String memo) throws Exception {
            this.timestamp = Instant.now().toString();
            this.previousHash = "0";
            this.operationType = operationType;
            this.fileHash = fileHash;
            this.user = user;
            this.memo = memo;
            this.hash = calcHash();
        }

        private String calcHash() throws Exception {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            String s = timestamp + "|" + previousHash + "|" + operationType + "|" + fileHash + "|" + user + "|" + memo;
            byte[] h = md.digest(s.getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder();
            for (byte b : h) sb.append(String.format("%02x", b));
            return sb.toString();
        }
    }

    static class Blockchain {
        private final List<Block> chain = new ArrayList<>();

        void addBlock(Block b) throws Exception {
            if (!chain.isEmpty()) b.previousHash = chain.get(chain.size() - 1).hash;
            b.hash = b.calcHash();
            chain.add(b);
        }

        boolean isValid() throws Exception {
            for (int i = 0; i < chain.size(); i++) {
                Block cur = chain.get(i);
                if (i == 0 && !"0".equals(cur.previousHash)) return false;
                if (i > 0 && !cur.previousHash.equals(chain.get(i - 1).hash)) return false;
                if (!cur.calcHash().equals(cur.hash)) return false;
            }
            return true;
        }

        String toJson() {
            StringBuilder sb = new StringBuilder();
            sb.append("[\n");
            for (int i = 0; i < chain.size(); i++) {
                Block b = chain.get(i);
                sb.append("  {\"timestamp\":\"").append(b.timestamp)
                        .append("\",\"previous_hash\":\"").append(b.previousHash)
                        .append("\",\"operation_type\":\"").append(b.operationType)
                        .append("\",\"file_hash\":\"").append(b.fileHash)
                        .append("\",\"user\":\"").append(b.user)
                        .append("\",\"memo\":\"").append(b.memo)
                        .append("\",\"hash\":\"").append(b.hash).append("\"}");
                if (i < chain.size() - 1) sb.append(",");
                sb.append("\n");
            }
            sb.append("]");
            return sb.toString();
        }

        static Blockchain fromJson(String json) {
            Blockchain bc = new Blockchain();
            if (json == null || json.trim().isEmpty()) return bc;
            String[] blocks = json.split("\\},\\s*\\{");
            for (String blk : blocks) {
                try {
                    String clean = blk.replaceAll("[\\[\\]\\{\\}]", "");
                    String[] parts = clean.split(",");
                    Map<String, String> map = new HashMap<>();
                    for (String part : parts) {
                        String[] kv = part.split(":", 2);
                        if (kv.length == 2) {
                            String k = kv[0].replace("\"", "").trim();
                            String v = kv[1].replace("\"", "").trim();
                            map.put(k, v);
                        }
                    }
                    Block b = new Block(map.get("file_hash"), map.get("operation_type"), map.get("user"), map.get("memo"));
                    b.timestamp = map.get("timestamp");
                    b.previousHash = map.get("previous_hash");
                    b.hash = map.get("hash");
                    bc.chain.add(b);
                } catch (Exception e) {
                    // skip malformed
                }
            }
            return bc;
        }
    }
}
