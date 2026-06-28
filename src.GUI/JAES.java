
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
import javax.swing.*;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;

public class JAES {

    // ===== 定数 =====
    private static final int AES_KEY_SIZE = 256;
    private static final int GCM_NONCE_LEN = 12;
    private static final int GCM_TAG_LEN = 16;
    private static final String OAEP_TRANSFORM = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding";
    private static final String BLOCKCHAIN_HEADER_STR = "BLOCKCHAIN_DATA_START\n";
    private static final byte[] BLOCKCHAIN_HEADER = BLOCKCHAIN_HEADER_STR.getBytes(StandardCharsets.UTF_8);
    private static final String PNG_EXT = ".jpng";

    private static final String JAVA_VERSION_HEADER_STR = "JAVA_VERSION_START\n";
    private static final byte[] JAVA_VERSION_HEADER = JAVA_VERSION_HEADER_STR.getBytes(StandardCharsets.UTF_8);
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
            System.err.println("⚠ キーディレクトリ作成に失敗しました: " + KEY_DIR);
        }
    }

    public static String getExtension(String filename) {
        int dot = filename.lastIndexOf('.');
        if (dot == -1)
            return ""; // 拡張子なし
        return filename.substring(dot + 1);
    }

    private static Path PRIV_PEM = KEY_DIR.resolve("private.pem");
    private static Path PUB_PEM = KEY_DIR.resolve("public.pem");
    private static Path CURRENT_PUB_KEY = PUB_PEM;
    private static boolean NOCLS_MODE = false;
    private static int n = 0; // 設定ファイルの値を使用するかの判定用変数
    private static boolean PortableMode = false; // ポータブルモード判定変数

public static void main(String[] args) {
    SplitMerge.initConfig();
    System.setProperty("file.encoding", "UTF-8");
    System.setProperty("sun.jnu.encoding", "UTF-8");

    try {
        Files.createDirectories(KEY_DIR);
        ensureKeyPair();
    } catch (Exception e) {
        JOptionPane.showMessageDialog(
                null,
                "起動エラー: " + e.getMessage(),
                "JAES",
                JOptionPane.ERROR_MESSAGE
        );
        return;
    }

    SwingUtilities.invokeLater(JAES::createGui);
}
private static JFrame frame;
private static JTextArea logArea;

private static JTextField encInputField;
private static JTextField encPublicKeyField;
private static JTextArea encMemoArea;

private static JTextField decInputField;
private static JTextArea decMemoArea;

private static JTextField pngInputField;
private static JTextField pngPublicKeyField;
private static JTextArea pngMemoArea;

private static JTextField chainInputField;
private static JTextField javaInputField;

private static void createGui() {
    frame = new JFrame("JAES - Java AES Encrypt System");
    frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
    frame.setSize(900, 700);
    frame.setLocationRelativeTo(null);

    JTabbedPane tabs = new JTabbedPane();

    tabs.addTab("暗号化", createEncryptTab());
    tabs.addTab("復号", createDecryptTab());
    tabs.addTab("PNG", createPngTab());
    tabs.addTab("ブロックチェーン", createChainTab());
    tabs.addTab("Java情報", createJavaTab());

    logArea = new JTextArea(8, 80);
    logArea.setEditable(false);

    JPanel root = new JPanel(new BorderLayout(10, 10));
    root.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));
    root.add(tabs, BorderLayout.CENTER);
    root.add(new JScrollPane(logArea), BorderLayout.SOUTH);

    frame.setContentPane(root);
    frame.setVisible(true);
}

private static JPanel createEncryptTab() {
    JPanel panel = new JPanel(new BorderLayout(10, 10));

    encInputField = new JTextField();
    encPublicKeyField = new JTextField(CURRENT_PUB_KEY.toString());
    encMemoArea = new JTextArea(5, 40);

    JPanel form = new JPanel(new GridBagLayout());
    GridBagConstraints gbc = baseGbc();

    addFileRow(form, gbc, 0, "入力ファイル", encInputField);
    addFileRow(form, gbc, 1, "公開鍵", encPublicKeyField);

    gbc.gridx = 0;
    gbc.gridy = 2;
    gbc.weightx = 0;
    form.add(new JLabel("メモ"), gbc);

    gbc.gridx = 1;
    gbc.weightx = 1;
    gbc.gridwidth = 2;
    form.add(new JScrollPane(encMemoArea), gbc);
    gbc.gridwidth = 1;

    JButton encryptButton = new JButton("暗号化して .jdec を作成");
    encryptButton.addActionListener(e -> encryptJdecGui());

    JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT));
    bottom.add(encryptButton);

    panel.add(form, BorderLayout.NORTH);
    panel.add(bottom, BorderLayout.SOUTH);

    return panel;
}

private static PublicKey getPublicKeyFromField(JTextField field) throws Exception {
    String keyPath = field.getText().trim();

    Path key = keyPath.isEmpty()
            ? CURRENT_PUB_KEY
            : Paths.get(keyPath);

    if (!Files.exists(key)) {
        throw new IOException("公開鍵が存在しません: " + key);
    }

    CURRENT_PUB_KEY = key;
    return loadPublicKeyFromPemOrDer(key);
}

private static byte[] loadBlobFromFile(Path in) throws Exception {
    String name = in.getFileName().toString();

    if (name.endsWith(PNG_EXT)) {
        BufferedImage img = ImageIO.read(in.toFile());
        if (img == null) {
            throw new IOException("PNGの読み込みに失敗しました。");
        }

        byte[] pixels = decodeFromImage(img);
        if (pixels.length < 4) {
            throw new IOException("PNGが不正です。");
        }

        ByteBuffer bb = ByteBuffer.wrap(pixels);
        int payloadLen = bb.getInt();

        if (payloadLen < 0 || payloadLen > pixels.length - 4) {
            throw new IOException("PNG内データ長が不正です。");
        }

        byte[] blob = new byte[payloadLen];
        bb.get(blob);
        return blob;
    }

    return Files.readAllBytes(in);
}
private static JPanel createDecryptTab() {
    JPanel panel = new JPanel(new BorderLayout(10, 10));

    decInputField = new JTextField();
    decMemoArea = new JTextArea(5, 40);

    JPanel form = new JPanel(new GridBagLayout());
    GridBagConstraints gbc = baseGbc();

    addFileRow(form, gbc, 0, "入力 .jdec / .jdec0", decInputField);

    gbc.gridx = 0;
    gbc.gridy = 1;
    gbc.weightx = 0;
    form.add(new JLabel("メモ"), gbc);

    gbc.gridx = 1;
    gbc.weightx = 1;
    gbc.gridwidth = 2;
    form.add(new JScrollPane(decMemoArea), gbc);
    gbc.gridwidth = 1;

    JButton decryptButton = new JButton("復号する");
    decryptButton.addActionListener(e -> decryptJdecGui());

    JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT));
    bottom.add(decryptButton);

    panel.add(form, BorderLayout.NORTH);
    panel.add(bottom, BorderLayout.SOUTH);

    return panel;
}

private static JPanel createPngTab() {
    JPanel panel = new JPanel(new BorderLayout(10, 10));

    pngInputField = new JTextField();
    pngPublicKeyField = new JTextField(CURRENT_PUB_KEY.toString());
    pngMemoArea = new JTextArea(5, 40);

    JPanel form = new JPanel(new GridBagLayout());
    GridBagConstraints gbc = baseGbc();

    addFileRow(form, gbc, 0, "入力ファイル / .jpng", pngInputField);
    addFileRow(form, gbc, 1, "公開鍵", pngPublicKeyField);

    gbc.gridx = 0;
    gbc.gridy = 2;
    gbc.weightx = 0;
    form.add(new JLabel("メモ"), gbc);

    gbc.gridx = 1;
    gbc.weightx = 1;
    gbc.gridwidth = 2;
    form.add(new JScrollPane(pngMemoArea), gbc);
    gbc.gridwidth = 1;

    JButton encPngButton = new JButton("PNG暗号化");
    encPngButton.addActionListener(e -> encryptPngGui());

    JButton decPngButton = new JButton("PNG復号");
    decPngButton.addActionListener(e -> decryptPngGui());

    JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT));
    bottom.add(encPngButton);
    bottom.add(decPngButton);

    panel.add(form, BorderLayout.NORTH);
    panel.add(bottom, BorderLayout.SOUTH);

    return panel;
}

private static JPanel createChainTab() {
    JPanel panel = new JPanel(new BorderLayout(10, 10));

    chainInputField = new JTextField();

    JPanel form = new JPanel(new GridBagLayout());
    GridBagConstraints gbc = baseGbc();

    addFileRow(form, gbc, 0, "対象ファイル", chainInputField);

    JButton verifyButton = new JButton("チェーン検証");
    verifyButton.addActionListener(e -> verifyChainGui());

    JButton exportButton = new JButton("チェーンJSON出力");
    exportButton.addActionListener(e -> exportChainGui());

    JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT));
    bottom.add(verifyButton);
    bottom.add(exportButton);

    panel.add(form, BorderLayout.NORTH);
    panel.add(bottom, BorderLayout.SOUTH);

    return panel;
}

private static JPanel createJavaTab() {
    JPanel panel = new JPanel(new BorderLayout(10, 10));

    javaInputField = new JTextField();

    JPanel form = new JPanel(new GridBagLayout());
    GridBagConstraints gbc = baseGbc();

    addFileRow(form, gbc, 0, "対象ファイル", javaInputField);

    JButton showButton = new JButton("Javaバージョン情報を表示");
    showButton.addActionListener(e -> showJavaVersionGui());

    JPanel bottom = new JPanel(new FlowLayout(FlowLayout.RIGHT));
    bottom.add(showButton);

    panel.add(form, BorderLayout.NORTH);
    panel.add(bottom, BorderLayout.SOUTH);

    return panel;
}

private static GridBagConstraints baseGbc() {
    GridBagConstraints gbc = new GridBagConstraints();
    gbc.insets = new Insets(8, 8, 8, 8);
    gbc.fill = GridBagConstraints.HORIZONTAL;
    return gbc;
}

private static void addFileRow(JPanel panel, GridBagConstraints gbc, int y, String label, JTextField field) {
    JButton browse = new JButton("参照");
    browse.addActionListener(e -> chooseFile(field));

    gbc.gridx = 0;
    gbc.gridy = y;
    gbc.weightx = 0;
    panel.add(new JLabel(label), gbc);

    gbc.gridx = 1;
    gbc.weightx = 1;
    panel.add(field, gbc);

    gbc.gridx = 2;
    gbc.weightx = 0;
    panel.add(browse, gbc);
}

private static void chooseFile(JTextField target) {
    JFileChooser chooser = new JFileChooser();
    int result = chooser.showOpenDialog(frame);
    if (result == JFileChooser.APPROVE_OPTION) {
        target.setText(chooser.getSelectedFile().getAbsolutePath());
    }
}

private static void log(String text) {
    logArea.append(text + "\n");
}

private static void error(String text) {
    JOptionPane.showMessageDialog(frame, text, "エラー", JOptionPane.ERROR_MESSAGE);
    log("❌ " + text);
}

    private static byte[] buildJavaVersionBytes() {
        return System.getProperty("java.version")
                .getBytes(StandardCharsets.UTF_8);
    }

    public static void exportBlockchainToFile(Path input) throws IOException {
        // 入力ファイルと同じフォルダに出す
        String name = input.getFileName().toString();

        // 拡張子を落とす（.jdec / .jpng / .jdec0 など）
        String base = name;
        int dot = name.lastIndexOf('.');
        if (dot > 0)
            base = name.substring(0, dot);

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
            throw new IOException("ブロックチェーンデータが見つかりませんでした: " + inputs);
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
        if (img == null)
            throw new IOException("PNGの読み込みに失敗しました: " + jpngPath);

        byte[] pixels = decodeFromImage(img); // 既存privateメソッド
        if (pixels.length < 4)
            return Optional.empty();

        ByteBuffer bb = ByteBuffer.wrap(pixels);
        int payloadLen = bb.getInt();
        if (payloadLen < 0 || payloadLen > pixels.length - 4)
            return Optional.empty();

        byte[] blob = new byte[payloadLen];
        bb.get(blob);

        return readBlockchainJsonIfAny(blob); // 既存privateメソッド
    }

    private static char[] readPassphrase() throws IOException {
    JPasswordField field = new JPasswordField();

    int result = JOptionPane.showConfirmDialog(
            frame,
            field,
            "秘密鍵のパスフレーズ",
            JOptionPane.OK_CANCEL_OPTION,
            JOptionPane.PLAIN_MESSAGE
    );

    if (result != JOptionPane.OK_OPTION) {
        throw new IOException("パスフレーズ入力がキャンセルされました。");
    }

    return field.getPassword();
}
    // ========= 一行入力 =========
    public static void input(String args) {
        Scanner scanner = new Scanner(System.in); // 標準入力を扱うScannerを作成
        System.out.print(" >> "); // プロンプトを表示
        String input = scanner.nextLine(); // 1行分の入力を読み取る
    }

    // ========= 画面を初期化 =========
    public static void clearConsole() {
        if (NOCLS_MODE) {
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
            System.out.println("画面クリアに失敗しました: " + e.getMessage());
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
                if (cj.isPresent())
                    return Blockchain.fromJson(cj.get());
            }
        } catch (Exception ignore) {
        }
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
                        if (cj.isPresent())
                            return Blockchain.fromJson(cj.get());
                    }
                }
            }
        } catch (Exception ignore) {
        }
        return new Blockchain();
    }

    // ========= 暗号フォーマット構築 =========
    // .jdec: [4B klen][encKey(RSA-OAEP)][12B nonce][ciphertext][16B tag] + HEADER +
    // (JSON gzip or plain)
    private static byte[] buildEncryptedBlobWithBaseChain(byte[] plaintext, PublicKey pub, String memo,
            Blockchain baseChain, boolean compressChainForJdec) throws Exception {
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
        bos.write(JAVA_VERSION_HEADER);
        bos.write(buildJavaVersionBytes());
        return bos.toByteArray();
    }

    // blob から復号。updateChain=true ならチェーン追記済みblobを返す
    // originalJdecOrNull != null のときは .jdec へ書戻す（GZIP圧縮で追記）
    // originalJdecOrNull == null のときは（PNGケース）可読JSONで updatedBlob を返す
    private static DecryptResult decryptFromBlob(byte[] blob, PrivateKey priv, String memo, boolean updateChain,
            Path originalJdecOrNull) throws Exception {
        warnJavaVersionDifference(blob);

        int split = indexOf(blob, BLOCKCHAIN_HEADER);
        byte[] cryptoPart;
        Blockchain chain;
        if (split >= 0) {
            cryptoPart = Arrays.copyOfRange(blob, 0, split);
            // 後続を圧縮/非圧縮のどちらでも解析
            String existingJson = readBlockchainJsonAfterHeader(
                    Arrays.copyOfRange(blob, split + BLOCKCHAIN_HEADER.length, blob.length));
            chain = (existingJson != null && !existingJson.trim().isEmpty())
                    ? Blockchain.fromJson(existingJson)
                    : new Blockchain();
        } else {
            cryptoPart = blob;
            chain = new Blockchain();
        }

        ByteBuffer buf = ByteBuffer.wrap(cryptoPart);
        if (buf.remaining() < 4)
            throw new IllegalArgumentException("Invalid blob");
        int keyLen = buf.getInt();
        if (keyLen <= 0 || buf.remaining() < keyLen + GCM_NONCE_LEN + GCM_TAG_LEN)
            throw new IllegalArgumentException("Invalid RSA key block");

        byte[] encKey = new byte[keyLen];
        buf.get(encKey);
        byte[] nonce = new byte[GCM_NONCE_LEN];
        buf.get(nonce);

        int remain = buf.remaining();
        if (remain <= GCM_TAG_LEN)
            throw new IllegalArgumentException("Invalid GCM block");
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
            bos.write(JAVA_VERSION_HEADER);
            bos.write(buildJavaVersionBytes());

            updatedBlobOrNull = bos.toByteArray();

            if (originalJdecOrNull != null) {
                Files.write(originalJdecOrNull, updatedBlobOrNull, StandardOpenOption.TRUNCATE_EXISTING,
                        StandardOpenOption.CREATE);
            }
        }
        return new DecryptResult(plaintext, updatedBlobOrNull);
    }

    // ========= PNG エンコード/デコード（圧縮なし：RGB直格納） =========
    private static BufferedImage encodeToImage(byte[] data) {
        int numPixels = (int) Math.ceil(data.length / 3.0);
        int width = (int) Math.ceil(Math.sqrt(numPixels));
        int height = (int) Math.ceil((double) numPixels / width);
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
    private static void writePngWithText(BufferedImage img, Path out, Map<String, String> textPairs)
            throws IOException {
        Iterator<ImageWriter> it = ImageIO.getImageWritersByFormatName("png");
        if (!it.hasNext())
            throw new IOException("PNG ImageWriter not found");
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
            for (Map.Entry<String, String> en : textPairs.entrySet()) {
                String key = en.getKey();
                for (int i = text.getLength() - 1; i >= 0; i--) {
                    IIOMetadataNode n = (IIOMetadataNode) text.item(i);
                    if ("tEXtEntry".equals(n.getNodeName())) {
                        String k = n.getAttribute("keyword");
                        if (key.equals(k))
                            text.removeChild(n);
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
        if (split < 0)
            return Optional.empty();
        String json = readBlockchainJsonAfterHeaderString(data, split + BLOCKCHAIN_HEADER.length);
        return (json == null) ? Optional.empty() : Optional.of(json);
    }

    private static String readBlockchainJsonAfterHeaderString(byte[] data, int offset) {
        byte[] tail = Arrays.copyOfRange(data, offset, data.length);
        return readBlockchainJsonAfterHeader(tail);
    }

    private static Optional<String> readJavaVersionIfAny(byte[] data) {
        int pos = indexOf(data, JAVA_VERSION_HEADER);
        if (pos < 0)
            return Optional.empty();

        byte[] versionBytes = Arrays.copyOfRange(
                data,
                pos + JAVA_VERSION_HEADER.length,
                data.length);

        String version = new String(versionBytes, StandardCharsets.UTF_8).trim();
        return version.isEmpty() ? Optional.empty() : Optional.of(version);
    }

    private static int parseJavaMajorVersion(String version) {
        try {
            if (version.startsWith("1.")) {
                return Integer.parseInt(version.split("\\.")[1]);
            }
            return Integer.parseInt(version.split("[\\.\\-\\+]")[0]);
        } catch (Exception e) {
            return -1;
        }
    }

    private static void showJavaVersionInfo(byte[] data) {
        Optional<String> embedded = readJavaVersionIfAny(data);

        if (!embedded.isPresent()) {
            System.out.println("ℹ Javaバージョン情報は見つかりませんでした。");
            return;
        }

        System.out.println("✅ 暗号化時のJavaバージョン: " + embedded.get());
        System.out.println("現在のJavaバージョン: " + System.getProperty("java.version"));

        int embeddedMajor = parseJavaMajorVersion(embedded.get());
        int currentMajor = Runtime.version().feature();

        if (embeddedMajor == currentMajor) {
            System.out.println("判定         : 一致");
        } else {
            System.out.println("判定         : 不一致（復号できない場合があります）");
        }
    }

    private static void warnJavaVersionDifference(byte[] blob) {
        Optional<String> embedded = readJavaVersionIfAny(blob);
        if (!embedded.isPresent())
            return;

        String embeddedVersion = embedded.get();
        String currentVersion = System.getProperty("java.version");

        int embeddedMajor = parseJavaMajorVersion(embeddedVersion);
        int currentMajor = Runtime.version().feature();

        if (embeddedMajor > 0 && embeddedMajor != currentMajor) {
            System.out.println("⚠ Javaバージョン差異があります。");
            System.out.println("  暗号化時 Java: " + embeddedVersion);
            System.out.println("  現在の Java: " + currentVersion);
            System.out.println("  バージョン差異により、復号できない場合があります。");
        }
    }

    private static String readBlockchainJsonAfterHeader(byte[] tail) {
        int versionPos = indexOf(tail, JAVA_VERSION_HEADER);
        if (versionPos >= 0) {
            tail = Arrays.copyOfRange(tail, 0, versionPos);
        }
        // まずGZIPとして試す
        try {
            ByteArrayInputStream bis = new ByteArrayInputStream(tail);
            GZIPInputStream gz = new GZIPInputStream(bis);
            ByteArrayOutputStream buf = new ByteArrayOutputStream();
            byte[] tmp = new byte[1024];
            int r;
            while ((r = gz.read(tmp)) != -1)
                buf.write(tmp, 0, r);
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
            return input.getParent() == null ? Paths.get(name.substring(0, name.length() - 5))
                    : input.getParent().resolve(name.substring(0, name.length() - 5));
        }
        return input.resolveSibling(name + ".dec");
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
            if (match)
                return i;
        }
        return -1;
    }


    private static void encryptJdecGui() {
    try {
        Path in = getInputPath(encInputField);
        if (in == null) return;

        Path out = in.resolveSibling(in.getFileName().toString() + ".jdec");

        Blockchain baseChain = tryLoadExistingChainFromJdec(out);

        byte[] blob = buildEncryptedBlobWithBaseChain(
                Files.readAllBytes(in),
                getPublicKeyFromField(encPublicKeyField),
                encMemoArea.getText(),
                baseChain,
                true
        );

        Files.write(out, blob, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        SplitMerge.split(out);

        log("✅ 暗号化完了: " + out);

    } catch (Exception e) {
        error(e.getMessage());
    }
}

private static void decryptJdecGui() {
    try {
        Path in = getInputPath(decInputField);
        if (in == null) return;

        Path out = guessDecryptedName(in);

        char[] pass = readPassphrase();

        DecryptResult res = decryptFromBlob(
                Files.readAllBytes(in),
                PrivateKeyProtector.loadEncrypted(PRIV_PEM, pass),
                decMemoArea.getText(),
                true,
                in
        );

        Files.write(out, res.plaintext, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        log("✅ 復号完了: " + out);

    } catch (Exception e) {
        error(e.getMessage());
    }
}

private static void encryptPngGui() {
    try {
        Path in = getInputPath(pngInputField);
        if (in == null) return;

        Path outPng = in.resolveSibling(in.getFileName().toString() + PNG_EXT);

        Blockchain baseChain = tryLoadExistingChainFromJpng(outPng);

        byte[] blob = buildEncryptedBlobWithBaseChain(
                Files.readAllBytes(in),
                getPublicKeyFromField(pngPublicKeyField),
                pngMemoArea.getText(),
                baseChain,
                false
        );

        ByteBuffer bb = ByteBuffer.allocate(4 + blob.length);
        bb.putInt(blob.length);
        bb.put(blob);

        BufferedImage img = encodeToImage(bb.array());

        Map<String, String> meta = new LinkedHashMap<>();
        meta.put("LastUpdated", Instant.now().toString());

        writePngWithText(img, outPng, meta);

        log("✅ PNG暗号化完了: " + outPng);

    } catch (Exception e) {
        error(e.getMessage());
    }
}

private static void decryptPngGui() {
    try {
        Path inPng = getInputPath(pngInputField);
        if (inPng == null) return;

        byte[] blob = loadBlobFromFile(inPng);

        String name = inPng.getFileName().toString();
        Path out;

        if (name.endsWith(PNG_EXT)) {
            out = inPng.getParent().resolve(name.substring(0, name.length() - PNG_EXT.length()));
        } else {
            out = inPng.resolveSibling(name + ".dec");
        }

        char[] pass = readPassphrase();

        DecryptResult res = decryptFromBlob(
                blob,
                PrivateKeyProtector.loadEncrypted(PRIV_PEM, pass),
                pngMemoArea.getText(),
                true,
                null
        );

        Files.write(out, res.plaintext, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        if (res.updatedBlob != null) {
            ByteBuffer bb2 = ByteBuffer.allocate(4 + res.updatedBlob.length);
            bb2.putInt(res.updatedBlob.length);
            bb2.put(res.updatedBlob);

            BufferedImage updated = encodeToImage(bb2.array());

            Map<String, String> meta = new LinkedHashMap<>();
            meta.put("LastUpdated", Instant.now().toString());

            writePngWithText(updated, inPng, meta);
        }

        log("✅ PNG復号完了: " + out);

    } catch (Exception e) {
        error(e.getMessage());
    }
}

private static void verifyChainGui() {
    try {
        Path in = getInputPath(chainInputField);
        if (in == null) return;

        byte[] blob = loadBlobFromFile(in);

        Optional<String> chainJson = readBlockchainJsonIfAny(blob);

        if (!chainJson.isPresent()) {
            log("ℹ ブロックチェーンデータが見つかりません。");
            return;
        }

        Blockchain chain = Blockchain.fromJson(chainJson.get());

        if (chain.isValid()) {
            log("✅ チェーンは整合しています。");
        } else {
            log("❌ チェーンに不整合があります。");
        }

    } catch (Exception e) {
        error(e.getMessage());
    }
}

private static void exportChainGui() {
    try {
        Path in = getInputPath(chainInputField);
        if (in == null) return;

        exportBlockchainToFile(in);

        log("✅ ブロックチェーンをエクスポートしました。");

    } catch (Exception e) {
        error(e.getMessage());
    }
}

private static void showJavaVersionGui() {
    try {
        Path in = getInputPath(javaInputField);
        if (in == null) return;

        byte[] blob = loadBlobFromFile(in);

        Optional<String> embedded = readJavaVersionIfAny(blob);

        if (!embedded.isPresent()) {
            log("ℹ Javaバージョン情報は見つかりませんでした。");
            return;
        }

        String embeddedVersion = embedded.get();
        String currentVersion = System.getProperty("java.version");

        int embeddedMajor = parseJavaMajorVersion(embeddedVersion);
        int currentMajor = Runtime.version().feature();

        log("=== Java Version Information ===");
        log("暗号化時 Java : " + embeddedVersion);
        log("現在の Java   : " + currentVersion);

        if (embeddedMajor == currentMajor) {
            log("判定          : 一致");
        } else {
            log("判定          : 不一致（復号できない場合があります）");
        }

    } catch (Exception e) {
        error(e.getMessage());
    }
}
private static Path getInputPath(JTextField field) {
    String input = field.getText().trim();

    if (input.isEmpty()) {
        error("入力ファイルを指定してください。");
        return null;
    }

    Path in = Paths.get(input);

    try {
        String ext = getExtension(in.toString());
        if (ext.endsWith("jdec0")) {
            in = SplitMerge.mergeFromPart0(in);
        }
    } catch (Exception e) {
        error("分割ファイルの結合に失敗しました: " + e.getMessage());
        return null;
    }

    if (!Files.exists(in)) {
        error("ファイルが存在しません: " + in);
        return null;
    }

    return in;
}
    private static String sha256Hex(byte[] data) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-256");
        byte[] h = md.digest(data);
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < h.length; i++)
            sb.append(String.format("%02x", h[i]));
        return sb.toString();
    }

    private static void ensureKeyPair() throws Exception {
        if (Files.exists(PRIV_PEM) && Files.exists(PUB_PEM))
            return;

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        // 🔐 パスフレーズ取得（初回のみ）
        char[] pass = readPassphraseForKeyGen();

        // 秘密鍵：暗号化して保存

        PrivateKeyProtector.saveEncrypted(
                kp.getPrivate(),
                pass,
                PRIV_PEM);
        // 公開鍵：そのまま
        writePem("PUBLIC KEY", kp.getPublic().getEncoded(), PUB_PEM);

        Arrays.fill(pass, '\0');
    }
private static char[] readPassphraseForKeyGen() throws IOException {

    while (true) {

        JPasswordField pass1 = new JPasswordField(20);
        JPasswordField pass2 = new JPasswordField(20);

        JPanel panel = new JPanel(new GridLayout(2, 2, 8, 8));
        panel.add(new JLabel("秘密鍵のパスフレーズ"));
        panel.add(pass1);
        panel.add(new JLabel("もう一度入力"));
        panel.add(pass2);

        int result = JOptionPane.showConfirmDialog(
                frame,
                panel,
                "秘密鍵の作成",
                JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE
        );

        if (result != JOptionPane.OK_OPTION) {
            throw new IOException("秘密鍵の作成をキャンセルしました。");
        }

        char[] p1 = pass1.getPassword();
        char[] p2 = pass2.getPassword();

        if (Arrays.equals(p1, p2)) {
            Arrays.fill(p2, '\0');
            return p1;
        }

        Arrays.fill(p1, '\0');
        Arrays.fill(p2, '\0');

        JOptionPane.showMessageDialog(
                frame,
                "パスフレーズが一致しません。",
                "入力エラー",
                JOptionPane.ERROR_MESSAGE
        );
    }
}

    private static void writeEncryptedPrivateKeyPem(
            PrivateKey privateKey,
            char[] passphrase,
            Path out) throws Exception {

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
                new PBEParameterSpec(salt, iterationCount));

        byte[] encrypted = cipher.doFinal(encoded);

        EncryptedPrivateKeyInfo epki = new EncryptedPrivateKeyInfo(cipher.getParameters(), encrypted);

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
        if (der == null)
            der = all;
        X509EncodedKeySpec spec = new X509EncodedKeySpec(der);
        return KeyFactory.getInstance("RSA").generatePublic(spec);
    }

    private static byte[] tryExtractDerFromPem(byte[] pemBytes, String type) {
        String s = new String(pemBytes, StandardCharsets.US_ASCII);
        String head = "-----BEGIN " + type + "-----";
        String foot = "-----END " + type + "-----";
        int i = s.indexOf(head);
        int j = s.indexOf(foot);
        if (i < 0 || j < 0)
            return null;
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
            for (int i = 0; i < h.length; i++)
                sb.append(String.format("%02x", h[i]));
            return sb.toString();
        }
    }

    static class Blockchain {
        private final List<Block> chain = new ArrayList<Block>();

        void addBlock(Block b) throws Exception {
            if (!chain.isEmpty())
                b.previousHash = chain.get(chain.size() - 1).hash;
            b.hash = b.calcHash();
            chain.add(b);
        }

        boolean isValid() throws Exception {
            for (int i = 0; i < chain.size(); i++) {
                Block cur = chain.get(i);
                if (i == 0 && !"0".equals(cur.previousHash))
                    return false;
                if (i > 0 && !cur.previousHash.equals(chain.get(i - 1).hash))
                    return false;
                if (!cur.calcHash().equals(cur.hash))
                    return false;
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
                if (i < chain.size() - 1)
                    sb.append(",");
                sb.append("\n");
            }
            sb.append("]");
            return sb.toString();
        }

        static Blockchain fromJson(String json) {
            Blockchain bc = new Blockchain();
            if (json == null || json.trim().isEmpty())
                return bc;
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
                    Block b = new Block(map.get("file_hash"), map.get("operation_type"), map.get("user"),
                            map.get("memo"));
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
            if (s == null)
                return "";
            String t = s.replace("\\", "\\\\").replace("\"", "\\\"");
            t = t.replace("\n", "\\n").replace("\r", "\\r");
            return t;
        }
    }
}
