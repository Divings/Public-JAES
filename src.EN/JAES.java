/**
 * BlockchainExporter.java
 * 
 * Copyright (c) 2025 Anvelk Innovations LLC / Innovation Craft Inc.
 * All rights reserved.
 */

import javax.crypto.*;
import javax.crypto.spec.PBEKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.crypto.spec.PBEParameterSpec;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;

import javax.imageio.ImageIO;
import javax.imageio.ImageTypeSpecifier;
import javax.imageio.ImageWriteParam;
import javax.imageio.ImageWriter;
import javax.imageio.IIOImage;
import javax.imageio.metadata.IIOMetadata;
import javax.imageio.metadata.IIOMetadataNode;
import javax.imageio.stream.ImageOutputStream;

import java.awt.image.BufferedImage;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.*;
import java.security.spec.*;
import java.time.Instant;
import java.util.*;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class JAES {

    // ===== 定数 =====
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_NONCE_LEN = 12;
    private static final int GCM_TAG_LEN = 16;
    private static final String OAEP_TRANSFORM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String BLOCKCHAIN_HEADER_STR = "BLOCKCHAIN_DATA_START\n";
    private static final byte[] BLOCKCHAIN_HEADER = BLOCKCHAIN_HEADER_STR.getBytes(StandardCharsets.UTF_8);
    private static final String PNG_EXT = ".jpng";
    
    // 鍵ファイル
    private static Path KEY_DIR;

    static {
        String appData = System.getenv("APPDATA");
        if (appData == null || appData.isEmpty()) {
            // Linux/macOS対応
            appData = System.getProperty("user.home") + "/.config";
        }
        KEY_DIR = Paths.get(appData, "JAES", "key");
        try {
            Files.createDirectories(KEY_DIR);
        } catch (IOException e) {
            System.err.println("⚠ Failed to create key directory: " + KEY_DIR);
    }
}
    public static String getExtension(String filename) {
    int dot = filename.lastIndexOf('.');
    if (dot == -1) return "";  // 拡張子なし
    return filename.substring(dot + 1);
}

    private static Path PRIV_PEM = KEY_DIR.resolve("private.pem");
    private static Path PUB_PEM  = KEY_DIR.resolve("public.pem");
    private static Path CURRENT_PUB_KEY = PUB_PEM;
    private static boolean NOCLS_MODE = false;
    private static int n = 0; // 設定ファイルの値を使用するかの判定用変数
    private static boolean PortableMode=false; // ポータブルモード判定変数
    public static void main(String[] args) {
        SplitMerge.initConfig();
        System.setProperty("file.encoding", "UTF-8");
        System.setProperty("sun.jnu.encoding", "UTF-8");
                
        // --- 公開鍵選択 ---
        if (args.length > 0) {
            if (args[0].equals("--exportpub")){
                try {
                    JAESPublicKeyExporter.exportToJarDirectory(true);
                
                } catch (IOException e) {
                    System.err.println("Failed to export public key: " + e.getMessage());
                }
                clearConsole();
            }
            if (args[0].equals("--nocls")){
                NOCLS_MODE=true;
            }

            if (args[0].equals("--portable")){
                String portableDir = args[1].replace("\"", "");
                Path base = Path.of(portableDir);
                Path dir = Paths.get(args[1]);

                if (Files.exists(dir) && Files.isDirectory(dir)) {
                    KEY_DIR = dir;
                    PRIV_PEM = KEY_DIR.resolve("private.pem");
                    PUB_PEM  = KEY_DIR.resolve("public.pem");
                    PortableMode=true;
                }
            }

            
            Path argKey = Paths.get(args[0]);
            
            if (Files.exists(argKey)) {
                CURRENT_PUB_KEY = argKey;
                n = 1;
            }
            
        }

        String cfgKeyPath = SplitMerge.getPublicKeyPath();
        if (n == 0){
            if (!cfgKeyPath.isEmpty()) {
                Path cfgKey = Paths.get(cfgKeyPath);

                if (Files.exists(cfgKey) && Files.isRegularFile(cfgKey)) {
                    CURRENT_PUB_KEY = cfgKey;
                    System.out.println("Using public key specified in config file: " + cfgKey);
                }
            }
        }
    
        // JAESPublicKeyExporter.exportToJarDirectory();
        try {
            Files.createDirectories(KEY_DIR);
            ensureKeyPair();
        } catch (Exception e) {
            System.err.println("Failed to prepare key directory: " + e.getMessage());
            return;
        }
        //BufferedReader br = new BufferedReader(new InputStreamReader(System.in, "UTF-8"))
        try (BufferedReader br = new BufferedReader(new InputStreamReader(System.in, "UTF-8"))) {
            while (true) {
                System.out.println();
                if (PortableMode){
                    System.out.println("Portable mode: Enabled");
                }else{
                    System.out.println("Portable mode: Disabled");
                }
                System.out.println("Current public key: " + CURRENT_PUB_KEY.getFileName());
                System.out.println("\nPlease select a mode:");
                System.out.println("1: Encrypt (output .jdec)");
                System.out.println("2: Decrypt (.jdec input)");
                System.out.println("3: Encrypt (output PNG)");
                System.out.println("4: Decrypt (PNG input) ");
                System.out.println("5: Verify blockchain (.jdec / .jpng)");
                System.out.println("6: Export blockchain");
                System.out.println("7: Exit");
                System.out.print("\nSelect >> ");
                //String choice = br.readLine();
                String choice = br.readLine();
                if (choice == null) break;
                choice = choice.trim();

                try {
                    if ("1".equals(choice)) {
                        System.out.print("Path of file to encrypt: ");
                        //String input = br.readLine().trim();  // まず文字列で受け取る
                        String input = br.readLine().trim();
                        if (input.isEmpty()) {
                            System.out.println("Operation canceled. Returning to menu.");
                            clearConsole();
                            continue; // または continue; （ループ構造に応じて）
                        }
                        
                        Path in = Paths.get(input);  // 空でない場合のみ Path に変換
                        
                        if (!Files.exists(in)) { System.out.println("❌ File does not exist"); clearConsole();continue; }
                        System.out.print("Memo (optional): ");
                        String memo = br.readLine();
                        Path out = in.resolveSibling(in.getFileName().toString() + ".jdec");

                        // ▶ 既存 .jdec があればチェーン継承
                        Blockchain baseChain = tryLoadExistingChainFromJdec(out);
                        byte[] blob;
                        

                        blob = buildEncryptedBlobWithBaseChain(
                        Files.readAllBytes(in),
                            loadPublicKeyFromPemOrDer(CURRENT_PUB_KEY),
                            memo,
                            baseChain,
                            true // compressChainForJdec
                        );

                        Files.write(out, blob, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                        
                        SplitMerge.split(out);
                        System.out.println("✅ Encryption completed (chain inherited): " + out);
                        clearConsole();
                    } else if ("2".equals(choice)) {
                        System.out.print("Path to .jdec file: ");
                        String input = br.readLine().trim();  // まず文字列で受け取る
                        
                        if (input.isEmpty()) {
                            System.out.println("Operation canceled. Returning to menu.");
                            clearConsole();
                            continue; // または continue; （ループ構造に応じて）
                        }
                        
                        Path in = Paths.get(input);  // 空でない場合のみ Path に変換
                        String ext = getExtension(in.toString());
                        if (ext.endsWith("jdec0")){
                        
                            in = SplitMerge.mergeFromPart0(in);
                        }
                        if (!Files.exists(in)) { System.out.println("❌ File does not exist"); continue; }
                        System.out.print("Memo (optional): ");
                        String memo = br.readLine();
                        Path out = guessDecryptedName(in);

                        char[] pass = readPassphrase();
                        // originalJdec を渡す → 追記書戻しはGZIP圧縮で
                        DecryptResult res = decryptFromBlob(Files.readAllBytes(in), PrivateKeyProtector.loadEncrypted(PRIV_PEM, pass), memo, true, in);
                        Files.write(out, res.plaintext, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
                        System.out.println("✅ Decryption completed (chain updated): " + out);
                        clearConsole();
                    } else if ("3".equals(choice)) {
                        System.out.print("Path of file to encrypt: ");
                        String input = br.readLine().trim();  // まず文字列で受け取る

                        if (input.isEmpty()) {
                            System.out.println("Operation canceled. Returning to menu.");
                            clearConsole();
                            continue; // または continue; （ループ構造に応じて）
                        }

                        Path in = Paths.get(input);  // 空でない場合のみ Path に変換

                        if (!Files.exists(in)) { System.out.println("❌ File does not exist"); continue; }
                        Path outPng = in.resolveSibling(in.getFileName().toString() + PNG_EXT);
                        System.out.println("[INFO] Output File Name: " + outPng);
                        System.out.print("Memo (optional): ");
                        String memo = br.readLine();

                        // ▶ 既存 .jpng があればチェーン継承
                        Blockchain baseChain = tryLoadExistingChainFromJpng(outPng);

                        byte[] blob = buildEncryptedBlobWithBaseChain(
                                Files.readAllBytes(in),
                                loadPublicKeyFromPemOrDer(CURRENT_PUB_KEY),
                                memo,
                                baseChain,
                                false  // compressChainForJdec = false → 可読JSONでPNGへ
                        );
                        ByteBuffer bb = ByteBuffer.allocate(4 + blob.length);
                        bb.putInt(blob.length);
                        bb.put(blob);
                        BufferedImage img = encodeToImage(bb.array());

                        Map<String,String> meta = new LinkedHashMap<String,String>();
                        meta.put("LastUpdated", Instant.now().toString());
                        writePngWithText(img, outPng, meta);
                        System.out.println("✅ Encryption result exported to PNG (chain inherited, LastUpdated added): " + outPng);
                        clearConsole();
                    } else if ("4".equals(choice)) {
                        System.out.print("Path to input PNG file: ");
                        String input = br.readLine().trim();  // まず文字列で受け取る

                        if (input.isEmpty()) {
                            System.out.println("Operation canceled. Returning to menu.");
                            clearConsole();
                            continue; // または continue; （ループ構造に応じて）
                        }

                        Path inPng = Paths.get(input).toAbsolutePath();;  // 空でない場合のみ Path に変換

                        if (!Files.exists(inPng)) { System.out.println("❌ File does not exist"); continue; }

                        // 自動で元の拡張子に復元（<元名>.jpng → <元名>）
                        String name = inPng.getFileName().toString();
                        Path out;
                        
                        if (name.endsWith(PNG_EXT)) {
                            out = inPng.getParent().resolveSibling(name.substring(0, name.length() - PNG_EXT.length()));
                        } else {
                            out = inPng.resolveSibling(name + ".dec");
                        }

                        // System.out.println("[INFO] 出力ファイル名: " + out);
                        System.out.print("Memo (optional): ");
                        String memo = br.readLine();

                        BufferedImage img = ImageIO.read(inPng.toFile());
                        byte[] pixels = decodeFromImage(img);
                        if (pixels.length < 4) { System.out.println("❌ Invalid PNG file"); clearConsole();continue; }
                        ByteBuffer bb = ByteBuffer.wrap(pixels);
                        int payloadLen = bb.getInt();
                        if (payloadLen < 0 || payloadLen > pixels.length - 4) { System.out.println("❌ Invalid embedded data length in PNG");clearConsole(); continue; }
                        byte[] blob = new byte[payloadLen];
                        bb.get(blob);
                        char[] pass = readPassphrase();

                        // 復号＋チェーン追記済みblob取得（PNGは可読JSONで書戻す）
                        DecryptResult res = decryptFromBlob(blob, PrivateKeyProtector.loadEncrypted(PRIV_PEM, pass), memo, true, null);
                        Files.write(out, res.plaintext, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

                        // PNGを書き戻し（チェーン更新反映）＋メタ LastUpdated 更新
                        if (res.updatedBlob != null) {
                            ByteBuffer bb2 = ByteBuffer.allocate(4 + res.updatedBlob.length);
                            bb2.putInt(res.updatedBlob.length);
                            bb2.put(res.updatedBlob);
                            BufferedImage updated = encodeToImage(bb2.array());

                            Map<String,String> meta = new LinkedHashMap<String,String>();
                            meta.put("LastUpdated", Instant.now().toString());
                            writePngWithText(updated, inPng, meta);
                        }
                        System.out.println("✅ Decrypted from PNG (chain and metadata updated): " + out);
                        clearConsole();
                    } else if ("5".equals(choice)) {
                        System.out.print("Path of file to verify (.jdec / .jpng): ");
                        String input = br.readLine().trim();  // まず文字列で受け取る

                        if (input.isEmpty()) {
                            System.out.println("Operation canceled. Returning to menu.");
                            clearConsole();
                            continue; // または continue; （ループ構造に応じて）
                        }

                        Path in = Paths.get(input);  // 空でない場合のみ Path に変換

                        if (!Files.exists(in)) { System.out.println("❌ File does not exist"); clearConsole();continue; }

                        String name = in.getFileName().toString();
                        byte[] blob;

                        if (name.endsWith(PNG_EXT)) {
                            // PNG から埋め込みデータ抽出
                            BufferedImage img = ImageIO.read(in.toFile());
                            byte[] pixels = decodeFromImage(img);
                            if (pixels.length < 4) { System.out.println("❌ Invalid PNG file"); clearConsole();continue; }
                            ByteBuffer bb = ByteBuffer.wrap(pixels);
                            int payloadLen = bb.getInt();
                            if (payloadLen < 0 || payloadLen > pixels.length - 4) {
                                System.out.println("❌ Invalid embedded data length in PNG");
                                clearConsole();
                                continue;
                            }
                            blob = new byte[payloadLen];
                            bb.get(blob);
                        } else {
                            // .jdec などバイナリをそのまま
                            blob = Files.readAllBytes(in);
                        }

                        Optional<String> chainJson = readBlockchainJsonIfAny(blob);
                        if (!chainJson.isPresent()) {
                            System.out.println("ℹ No blockchain data found");
                        } else {
                            Blockchain chain = Blockchain.fromJson(chainJson.get());
                            boolean ok = false;
                            try { ok = chain.isValid(); } catch (Exception ignore) {}
                            System.out.println(ok ? "✅ The chain is aligned." : "❌ Blockchain integrity check failed");
                            clearConsole();
                        }
                    } else if ("6".equals(choice)) {
                        System.out.print("Path of file to export (.jdec / .jpng): ");
                        String input = br.readLine().trim();  // まず文字列で受け取る

                        if (input.isEmpty()) {
                            System.out.println("Operation canceled. Returning to menu.");
                            clearConsole();
                            continue; // または continue; （ループ構造に応じて）
                        }

                        Path in = Paths.get(input);  // 空でない場合のみ Path に変換
                        exportBlockchainToFile(in);
                        System.out.print("Blockchain exported successfully.");
                        clearConsole();
                        continue;
                    } else if ("7".equals(choice)) {
                        System.out.println("👋 Exiting.");
                        break;

                    } else {
                        System.out.println("❌ Invalid selection");
                        clearConsole();
                    }
                    
                } catch (Exception ex) {
                    System.err.println("⚠ Error: " + ex.getMessage());
                    clearConsole();
                }
            }
        } catch (Exception e) {
            System.err.println("⚠ Runtime error: " + e.getMessage());
        }
    }

    public static void exportBlockchainToFile(Path input) throws IOException {
    // 入力ファイルと同じフォルダに出す
    String name = input.getFileName().toString();

    // 拡張子を落とす（.jdec / .jpng / .jdec0 など）
    String base = name;
    int dot = name.lastIndexOf('.');
    if (dot > 0) base = name.substring(0, dot);

    // 例: sample.jdec -> sample.chain.json
    Path outFile = input.resolveSibling(base + ".chain.json");

    exportBlockchainToFile(input, outFile); // 2引数版に委譲
}

    // ================================
// ブロックチェーンJSONを書き出し（.jdec / .jpng 両対応）
// ================================
public static void exportBlockchainToFile(Path inputs, Path outFile) throws IOException {
    String name = inputs.getFileName().toString().toLowerCase(Locale.ROOT);

    Optional<String> chainJson;

    if (name.endsWith(".jpng")) {
        chainJson = extractBlockchainFromJpng(inputs);
    } else {
        // .jdec / .jdec0 / その他は「バイナリ末尾にチェーンが付く」扱いで読む
        // ※ .jdec0 分割ファイル対応をしたい場合は、既存の SplitMerge.mergeFromPart0 をここで呼ぶのが安全
        chainJson = extractBlockchainFromJdec(inputs);
    }

    if (!chainJson.isPresent() || chainJson.get().trim().isEmpty()) {
        throw new IOException("Blockchain data not found: " + inputs);
    }

    Files.write(outFile, chainJson.get().getBytes(StandardCharsets.UTF_8),
            StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
}

private static Optional<String> extractBlockchainFromJdec(Path jdecPath) throws IOException {
    Path p = jdecPath;

    // 分割 .jdec0 を使っている場合のケア（あなたの実装に合わせて）
    String lower = p.getFileName().toString().toLowerCase(Locale.ROOT);
    if (lower.endsWith("jdec0")) {
        // 既にJAES内で使っている想定のヘルパー
        p = SplitMerge.mergeFromPart0(p);
    }

    byte[] data = Files.readAllBytes(p);
    return readBlockchainJsonIfAny(data); // 既存privateメソッド
}

private static Optional<String> extractBlockchainFromJpng(Path jpngPath) throws IOException {
    BufferedImage img = ImageIO.read(jpngPath.toFile());
    if (img == null) throw new IOException("PNG Read Faild: " + jpngPath);

    byte[] pixels = decodeFromImage(img); // 既存privateメソッド
    if (pixels.length < 4) return Optional.empty();

    ByteBuffer bb = ByteBuffer.wrap(pixels);
    int payloadLen = bb.getInt();
    if (payloadLen < 0 || payloadLen > pixels.length - 4) return Optional.empty();

    byte[] blob = new byte[payloadLen];
    bb.get(blob);

    return readBlockchainJsonIfAny(blob); // 既存privateメソッド
}

private static char[] readPassphrase() throws IOException {
    Console console = System.console();
    if (console == null) {
        throw new IllegalStateException(
            "Console is not available (cannot be used in IDE or redirected execution)"
        );
    }
    return console.readPassword("Private key passphrase: ");
}

    // ========= 一行入力 =========
    public static void input(String args) {
        Scanner scanner = new Scanner(System.in);  // 標準入力を扱うScannerを作成
        System.out.print(" >> ");                  // プロンプトを表示
        String input = scanner.nextLine();         // 1行分の入力を読み取る
    }

    // ========= 画面を初期化 =========
    public static void clearConsole() {
        if (NOCLS_MODE){
            return;
        }
        input(" >>");
        try {
            if (System.getProperty("os.name").startsWith("Windows")) {
                new ProcessBuilder("cmd", "/c", "cls").inheritIO().start().waitFor();
            } else {
                new ProcessBuilder("clear").inheritIO().start().waitFor();
            }
        } catch (Exception e) {
            System.out.println("Failed to clear console: " + e.getMessage());
        }
    }

    // ========= 復号結果ホルダ =========
    static class DecryptResult {
        public final byte[] plaintext;
        public final byte[] updatedBlob; // チェーン追記後の .jdec相当データ（PNG再パックや .jdec 書戻しに使用）

        DecryptResult(byte[] plaintext, byte[] updatedBlob) {
            this.plaintext = plaintext;
            this.updatedBlob = updatedBlob;
        }
    }

    // ========= 既存チェーン継承ユーティリティ =========

    private static Blockchain tryLoadExistingChainFromJdec(Path jdecPath) {
        try {
            if (Files.exists(jdecPath)) {
                byte[] existing = Files.readAllBytes(jdecPath);
                Optional<String> cj = readBlockchainJsonIfAny(existing);
                if (cj.isPresent()) return Blockchain.fromJson(cj.get());
            }
        } catch (Exception ignore) {}
        return new Blockchain();
    }

    private static Blockchain tryLoadExistingChainFromJpng(Path jpngPath) {
        try {
            if (Files.exists(jpngPath)) {
                BufferedImage img = ImageIO.read(jpngPath.toFile());
                byte[] pixels = decodeFromImage(img);
                if (pixels.length >= 4) {
                    ByteBuffer bb = ByteBuffer.wrap(pixels);
                    int payloadLen = bb.getInt();
                    if (payloadLen >= 0 && payloadLen <= pixels.length - 4) {
                        byte[] blob = new byte[payloadLen];
                        bb.get(blob);
                        Optional<String> cj = readBlockchainJsonIfAny(blob);
                        if (cj.isPresent()) return Blockchain.fromJson(cj.get());
                    }
                }
            }
        } catch (Exception ignore) {}
        return new Blockchain();
    }

    // ========= 暗号フォーマット構築 =========
    // .jdec: [4B klen][encKey(RSA-OAEP)][12B nonce][ciphertext][16B tag] + HEADER + (JSON gzip or plain)
    private static byte[] buildEncryptedBlobWithBaseChain(byte[] plaintext, PublicKey pub, String memo, Blockchain baseChain, boolean compressChainForJdec) throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("AES");
        kg.init(AES_KEY_SIZE);
        SecretKey aesKey = kg.generateKey();

        byte[] nonce = new byte[GCM_NONCE_LEN];
        new SecureRandom().nextBytes(nonce);

        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, aesKey, new GCMParameterSpec(GCM_TAG_LEN * 8, nonce));
        byte[] cipherAll = aes.doFinal(plaintext);
        int ctLen = cipherAll.length - GCM_TAG_LEN;
        byte[] ciphertext = Arrays.copyOfRange(cipherAll, 0, ctLen);
        byte[] tag = Arrays.copyOfRange(cipherAll, ctLen, cipherAll.length);

        Cipher rsa = Cipher.getInstance(OAEP_TRANSFORM);
        rsa.init(Cipher.ENCRYPT_MODE, pub);
        byte[] encKey = rsa.doFinal(aesKey.getEncoded());

        ByteBuffer header = ByteBuffer.allocate(4 + encKey.length + nonce.length + ciphertext.length + tag.length);
        header.putInt(encKey.length);
        header.put(encKey);
        header.put(nonce);
        header.put(ciphertext);
        header.put(tag);

        Blockchain chain = (baseChain != null) ? baseChain : new Blockchain();
        String user = System.getProperty("user.name", "unknown");
        String fileHash = sha256Hex(ciphertext);
        chain.addBlock(new Block(fileHash, "Encrypt", user, memo));

        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        bos.write(header.array());
        bos.write(BLOCKCHAIN_HEADER);

        // チェーンJSONの書き込み（.jdec は gzip、.jpng はプレーン）
        byte[] json = chain.toJson().getBytes(StandardCharsets.UTF_8);
        if (compressChainForJdec) {
            ByteArrayOutputStream gzBuf = new ByteArrayOutputStream();
            GZIPOutputStream gz = new GZIPOutputStream(gzBuf);
            gz.write(json);
            gz.close();
            bos.write(gzBuf.toByteArray());
        } else {
            bos.write(json);
        }
        return bos.toByteArray();
    }

    // blob から復号。updateChain=true ならチェーン追記済みblobを返す
    // originalJdecOrNull != null のときは .jdec へ書戻す（GZIP圧縮で追記）
    // originalJdecOrNull == null のときは（PNGケース）可読JSONで updatedBlob を返す
    private static DecryptResult decryptFromBlob(byte[] blob, PrivateKey priv, String memo, boolean updateChain, Path originalJdecOrNull) throws Exception {
        int split = indexOf(blob, BLOCKCHAIN_HEADER);
        byte[] cryptoPart;
        Blockchain chain;
        if (split >= 0) {
            cryptoPart = Arrays.copyOfRange(blob, 0, split);
            // 後続を圧縮/非圧縮のどちらでも解析
            String existingJson = readBlockchainJsonAfterHeader(Arrays.copyOfRange(blob, split + BLOCKCHAIN_HEADER.length, blob.length));
            chain = (existingJson != null && !existingJson.trim().isEmpty())
                    ? Blockchain.fromJson(existingJson) : new Blockchain();
        } else {
            cryptoPart = blob;
            chain = new Blockchain();
        }

        ByteBuffer buf = ByteBuffer.wrap(cryptoPart);
        if (buf.remaining() < 4) throw new IllegalArgumentException("Invalid blob");
        int keyLen = buf.getInt();
        if (keyLen <= 0 || buf.remaining() < keyLen + GCM_NONCE_LEN + GCM_TAG_LEN)
            throw new IllegalArgumentException("Invalid RSA key block");

        byte[] encKey = new byte[keyLen];
        buf.get(encKey);
        byte[] nonce = new byte[GCM_NONCE_LEN];
        buf.get(nonce);

        int remain = buf.remaining();
        if (remain <= GCM_TAG_LEN) throw new IllegalArgumentException("Invalid GCM block");
        byte[] ciphertext = new byte[remain - GCM_TAG_LEN];
        buf.get(ciphertext);
        byte[] tag = new byte[GCM_TAG_LEN];
        buf.get(tag);

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

        // チェーン更新
        String user = System.getProperty("user.name", "unknown");
        String fileHash = sha256Hex(ciphertext);
        chain.addBlock(new Block(fileHash, "Decrypt", user, memo));

        byte[] updatedBlobOrNull = null;
        if (updateChain) {
            ByteArrayOutputStream bos = new ByteArrayOutputStream();
            bos.write(cryptoPart);
            bos.write(BLOCKCHAIN_HEADER);
            // 書戻し形式を分岐：.jdec は GZIP、PNGは可読JSON
            byte[] json = chain.toJson().getBytes(StandardCharsets.UTF_8);
            if (originalJdecOrNull != null) {
                ByteArrayOutputStream gzBuf = new ByteArrayOutputStream();
                GZIPOutputStream gz = new GZIPOutputStream(gzBuf);
                gz.write(json);
                gz.close();
                bos.write(gzBuf.toByteArray());
            } else {
                bos.write(json);
            }
            updatedBlobOrNull = bos.toByteArray();

            if (originalJdecOrNull != null) {
                Files.write(originalJdecOrNull, updatedBlobOrNull, StandardOpenOption.TRUNCATE_EXISTING, StandardOpenOption.CREATE);
            }
        }
        return new DecryptResult(plaintext, updatedBlobOrNull);
    }

    // ========= PNG エンコード/デコード（圧縮なし：RGB直格納） =========
    private static BufferedImage encodeToImage(byte[] data) {
        int numPixels = (int)Math.ceil(data.length / 3.0);
        int width = (int)Math.ceil(Math.sqrt(numPixels));
        int height = (int)Math.ceil((double)numPixels / width);
        BufferedImage img = new BufferedImage(width, height, BufferedImage.TYPE_INT_RGB);
        int idx = 0;
        for (int y = 0; y < height; y++) {
            for (int x = 0; x < width; x++) {
                int r = idx < data.length ? (data[idx++] & 0xFF) : 0;
                int g = idx < data.length ? (data[idx++] & 0xFF) : 0;
                int b = idx < data.length ? (data[idx++] & 0xFF) : 0;
                int rgb = (r << 16) | (g << 8) | b;
                img.setRGB(x, y, rgb);
            }
        }
        return img;
    }

    private static byte[] decodeFromImage(BufferedImage img) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        for (int y = 0; y < img.getHeight(); y++) {
            for (int x = 0; x < img.getWidth(); x++) {
                int rgb = img.getRGB(x, y);
                bos.write((rgb >> 16) & 0xFF);
                bos.write((rgb >> 8) & 0xFF);
                bos.write(rgb & 0xFF);
            }
        }
        return bos.toByteArray();
    }

    // ========= PNG 書き込み（tEXt: LastUpdated 付） =========
    private static void writePngWithText(BufferedImage img, Path out, Map<String,String> textPairs) throws IOException {
        Iterator<ImageWriter> it = ImageIO.getImageWritersByFormatName("png");
        if (!it.hasNext()) throw new IOException("PNG ImageWriter not found");
        ImageWriter writer = it.next();
        ImageWriteParam param = writer.getDefaultWriteParam();
        ImageTypeSpecifier type = ImageTypeSpecifier.createFromRenderedImage(img);
        IIOMetadata metadata = writer.getDefaultImageMetadata(type, param);

        String fmt = "javax_imageio_png_1.0";
        IIOMetadataNode root;
        try {
            root = (IIOMetadataNode) metadata.getAsTree(fmt);
        } catch (Exception e) {
            root = new IIOMetadataNode(fmt);
        }

        IIOMetadataNode text = null;
        for (int i = 0; i < root.getLength(); i++) {
            if ("tEXt".equals(root.item(i).getNodeName())) {
                text = (IIOMetadataNode) root.item(i);
                break;
            }
        }
        if (text == null) {
            text = new IIOMetadataNode("tEXt");
            root.appendChild(text);
        }

        if (textPairs != null) {
            for (Map.Entry<String,String> en : textPairs.entrySet()) {
                String key = en.getKey();
                for (int i = text.getLength() - 1; i >= 0; i--) {
                    IIOMetadataNode n = (IIOMetadataNode) text.item(i);
                    if ("tEXtEntry".equals(n.getNodeName())) {
                        String k = n.getAttribute("keyword");
                        if (key.equals(k)) text.removeChild(n);
                    }
                }
                IIOMetadataNode entry = new IIOMetadataNode("tEXtEntry");
                entry.setAttribute("keyword", key);
                entry.setAttribute("value", en.getValue() == null ? "" : en.getValue());
                text.appendChild(entry);
            }
        }

        try {
            metadata.mergeTree(fmt, root);
        } catch (Exception e) {
            throw new IOException("PNG metadata merge failed: " + e.getMessage(), e);
        }

        try (ImageOutputStream ios = ImageIO.createImageOutputStream(out.toFile())) {
            writer.setOutput(ios);
            writer.write(null, new IIOImage(img, null, metadata), param);
        } finally {
            writer.dispose();
        }
    }

    // ========= チェーン読み出し（圧縮/非圧縮 自動判定） =========
    private static Optional<String> readBlockchainJsonIfAny(byte[] data) {
        int split = indexOf(data, BLOCKCHAIN_HEADER);
        if (split < 0) return Optional.empty();
        String json = readBlockchainJsonAfterHeaderString(data, split + BLOCKCHAIN_HEADER.length);
        return (json == null) ? Optional.empty() : Optional.of(json);
    }

    private static String readBlockchainJsonAfterHeaderString(byte[] data, int offset) {
        byte[] tail = Arrays.copyOfRange(data, offset, data.length);
        return readBlockchainJsonAfterHeader(tail);
    }

    private static String readBlockchainJsonAfterHeader(byte[] tail) {
        // まずGZIPとして試す
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(tail);
            GZIPInputStream gz = new GZIPInputStream(bis);
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] tmp = new byte[1024];
            int r;
            while ((r = gz.read(tmp)) != -1) buf.write(tmp, 0, r);
            gz.close();
            return new String(buf.toByteArray(), StandardCharsets.UTF_8);
        } catch (Exception ignored) {
            // 失敗したらプレーンJSONとして扱う
            try {
                return new String(tail, StandardCharsets.UTF_8);
            } catch (Exception e2) {
                return null;
            }
        }
    }

    private static Path guessDecryptedName(Path input) {
        String name = input.getFileName().toString();
        if (name.endsWith(".jdec")) {
            return input.getParent() == null ?
                    Paths.get(name.substring(0, name.length() - 5)) :
                    input.getParent().resolve(name.substring(0, name.length() - 5));
        }
        return input.resolveSibling(name + ".dec");
    }

    private static int indexOf(byte[] data, byte[] pattern) {
        for (int i = 0; i <= data.length - pattern.length; i++) {
            boolean match = true;
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) { match = false; break; }
            }
            if (match) return i;
        }
        return -1;
    }

    private static String sha256Hex(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] h = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < h.length; i++) sb.append(String.format("%02x", h[i]));
        return sb.toString();
    }

private static void ensureKeyPair() throws Exception {
    if (Files.exists(PRIV_PEM) && Files.exists(PUB_PEM)) return;

    KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
    kpg.initialize(2048);
    KeyPair kp = kpg.generateKeyPair();

    // 🔐 パスフレーズ取得（初回のみ）
    char[] pass = readPassphraseForKeyGen();

    // 秘密鍵：暗号化して保存

PrivateKeyProtector.saveEncrypted(
    kp.getPrivate(),
    pass,
    PRIV_PEM
);
    // 公開鍵：そのまま
    writePem("PUBLIC KEY", kp.getPublic().getEncoded(), PUB_PEM);

    Arrays.fill(pass, '\0');
}

private static char[] readPassphraseForKeyGen() throws IOException {
    Console console = System.console();
    if (console == null) {
        throw new IllegalStateException("Console is not available");
    }

    char[] p1 = console.readPassword("Private key passphrase: ");
    char[] p2 = console.readPassword("Enter again: ");

    if (!Arrays.equals(p1, p2)) {
        throw new IllegalArgumentException("Passphrases do not match");
    }
    Arrays.fill(p2, '\0');
    return p1;
}

private static void writeEncryptedPrivateKeyPem(
        PrivateKey privateKey,
        char[] passphrase,
        Path out
) throws Exception {

    byte[] encoded = privateKey.getEncoded(); // PKCS#8

    // Java標準PBE（OpenSSL互換）
    String algo = "PBEWithSHA1AndDESede";
    int iterationCount = 100_000;

    byte[] salt = SecureRandom.getInstanceStrong().generateSeed(16);

    PBEKeySpec pbeKeySpec = new PBEKeySpec(passphrase);
    SecretKeyFactory skf = SecretKeyFactory.getInstance(algo);
    SecretKey pbeKey = skf.generateSecret(pbeKeySpec);

    Cipher cipher = Cipher.getInstance(algo);
    cipher.init(
        Cipher.ENCRYPT_MODE,
        pbeKey,
        new PBEParameterSpec(salt, iterationCount)
    );

    byte[] encrypted = cipher.doFinal(encoded);

    EncryptedPrivateKeyInfo epki =
        new EncryptedPrivateKeyInfo(cipher.getParameters(), encrypted);

    byte[] der = epki.getEncoded();

    writePem("ENCRYPTED PRIVATE KEY", der, out);
}

    private static void writePem(String type, byte[] der, Path out) throws IOException {
    // AppData配下のファイル名を決定
    String fileName;
    if (type.toLowerCase().contains("private")) {
        fileName = "private.pem";
    } else if (type.toLowerCase().contains("public")) {
        fileName = "public.pem";
    } else {
        fileName = type.replaceAll("\\s+", "_").toLowerCase() + ".pem";
    }

    Path pemOut = KEY_DIR.resolve(fileName);

    // PEM形式で書き出し
    String b64 = Base64.getEncoder().encodeToString(der);
    try (BufferedWriter w = Files.newBufferedWriter(pemOut, StandardCharsets.US_ASCII)) {
        w.write("-----BEGIN " + type + "-----\n");
        for (int i = 0; i < b64.length(); i += 64) {
            w.write(b64.substring(i, Math.min(i + 64, b64.length())) + "\n");
        }
        w.write("-----END " + type + "-----\n");
    }
}

    private static PublicKey loadPublicKeyFromPemOrDer(Path p) throws Exception {
        byte[] all = Files.readAllBytes(p);
        byte[] der = tryExtractDerFromPem(all, "PUBLIC KEY");
        if (der == null) der = all;
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
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

    // ========= Blockchain =========
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
            for (int i = 0; i < h.length; i++) sb.append(String.format("%02x", h[i]));
            return sb.toString();
        }
    }

    static class Blockchain {
        private final List<Block> chain = new ArrayList<Block>();

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
                sb.append("  {\"timestamp\":\"").append(esc(b.timestamp))
                  .append("\",\"previous_hash\":\"").append(esc(b.previousHash))
                  .append("\",\"operation_type\":\"").append(esc(b.operationType))
                  .append("\",\"file_hash\":\"").append(esc(b.fileHash))
                  .append("\",\"user\":\"").append(esc(b.user))
                  .append("\",\"memo\":\"").append(esc(b.memo))
                  .append("\",\"hash\":\"").append(esc(b.hash)).append("\"}");
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
            for (int i = 0; i < blocks.length; i++) {
                String blk = blocks[i];
                try {
                    String clean = blk.replaceAll("[\\[\\]\\{\\}]", "");
                    String[] parts = clean.split(",");
                    Map<String, String> map = new HashMap<String, String>();
                    for (int j = 0; j < parts.length; j++) {
                        String part = parts[j];
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
                    // 壊れたブロックはスキップ
                }
            }
            return bc;
        }

        private static String esc(String s) {
            if (s == null) return "";
            String t = s.replace("\\", "\\\\").replace("\"", "\\\"");
            t = t.replace("\n", "\\n").replace("\r", "\\r");
            return t;
        }
    }
}
