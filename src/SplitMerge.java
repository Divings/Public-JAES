import java.io.*;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.nio.file.*;
import java.security.MessageDigest;
import java.util.*;

/**
 * EncryptSecureDEC / JAES 用 SplitMerge
 * - JSON 自作
 * - 設定ファイルは JAR と同じフォルダ
 * - .jdec 分割
 * - delmode 対応
 * - half モードは常に 0,1 の２分割固定
 */
public class SplitMerge {

    /* ============================================================
       JSON（自作） org.json 不要
    ============================================================ */
    private static class MinimalJSONObject {
        private final Map<String, String> map = new LinkedHashMap<>();

        public MinimalJSONObject() {}

        public MinimalJSONObject(String json) {
            json = json.trim();
            if (json.startsWith("{")) json = json.substring(1);
            if (json.endsWith("}")) json = json.substring(0, json.length() - 1);

            if (json.isEmpty()) return;

            String[] pairs = json.split(",");
            for (String pair : pairs) {
                String[] kv = pair.split(":", 2);
                if (kv.length != 2) continue;

                String key = kv[0].trim().replace("\"", "");
                String val = kv[1].trim().replace("\"", "");
                map.put(key, val);
            }
        }

        public void put(String key, Object value) {
            map.put(key, value.toString());
        }

        public String getString(String key) {
            return map.get(key);
        }

        public int getInt(String key) {
            return Integer.parseInt(map.get(key));
        }

        public boolean has(String key) {
            return map.containsKey(key);
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder("{");
            boolean first = true;
            for (var e : map.entrySet()) {
                if (!first) sb.append(",");
                sb.append("\"").append(e.getKey()).append("\":");
                sb.append("\"").append(e.getValue()).append("\"");
                first = false;
            }
            sb.append("}");
            return sb.toString();
        }
    }

    /* ============================================================
       SHA256
    ============================================================ */
    public static String sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] digest = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : digest) sb.append(String.format("%02x", b));
            return sb.toString();
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /* ============================================================
       JAR と同じ場所を返す
    ============================================================ */
    public static Path getJarDir() {
        try {
            URI uri = SplitMerge.class.getProtectionDomain()
                    .getCodeSource()
                    .getLocation()
                    .toURI();
            return Path.of(uri).getParent();
        } catch (Exception e) {
            return Path.of(".").toAbsolutePath().normalize();
        }
    }

    /* ============================================================
       設定ファイル
    ============================================================ */
    private static final Path CONFIG_PATH;

    static {
        CONFIG_PATH = getJarDir().resolve("split_config.ini");
    }

    public static void initConfig() {
        if (Files.exists(CONFIG_PATH)) return;

        try (BufferedWriter bw = Files.newBufferedWriter(CONFIG_PATH, StandardCharsets.UTF_8)) {
            bw.write("[Split]\n");
            bw.write("enabled=false\n");
            bw.write("mode=half\n");
            bw.write("parts=2\n");
            bw.write("delmode=false\n");
            bw.write("public_key_path=\n");
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
    }

    public static Map<String, String> loadSettings() {
        initConfig();

        Map<String, String> map = new HashMap<>();
        map.put("enabled", "false");
        map.put("mode", "half");
        map.put("parts", "2");
        map.put("delmode", "false");
        map.put("public_key_path", "");

        try {
            for (String line : Files.readAllLines(CONFIG_PATH, StandardCharsets.UTF_8)) {
                if (!line.contains("=")) continue;
                String[] kv = line.split("=", 2);
                map.put(kv[0].trim(), kv[1].trim());
            }
        } catch (IOException ignored) {}

        // 改行や BOM などを完全除去
        map.replaceAll((k, v) -> v.trim());

        return map;
    }

    /* ============================================================
       ヘッダー書き込み
    ============================================================ */
    private static void writePart(Path out, int index, int total, String originalName, byte[] data) {
        try (OutputStream os = Files.newOutputStream(out)) {

            MinimalJSONObject header = new MinimalJSONObject();
            header.put("original_name", originalName);
            header.put("part_index", index);
            header.put("total_parts", total);
            header.put("chunk_size", data.length);
            header.put("sha256", sha256(data));

            byte[] headerRaw = header.toString().getBytes(StandardCharsets.UTF_8);

            ByteBuffer bb = ByteBuffer.allocate(4);
            bb.putInt(headerRaw.length);
            os.write(bb.array());

            os.write(headerRaw);
            os.write(data);

        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    public static String getPublicKeyPath(){
        Map<String, String> cfg = loadSettings();
        return cfg.getOrDefault("public_key_path", "").trim();
    }

    /* ============================================================
       分割（.jdecX） + delmode対応
    ============================================================ */
    public static List<Path> split(Path file) throws IOException {

        Map<String, String> cfg = loadSettings();
        boolean enabled = Boolean.parseBoolean(cfg.get("enabled"));
        if (!enabled) {
            System.out.println("分割設定が無効のため分割しません。");
            return null;
        }

        String mode = cfg.get("mode").trim();
        int parts = Integer.parseInt(cfg.get("parts"));
        boolean delmode = Boolean.parseBoolean(cfg.get("delmode"));

        long totalSize = Files.size(file);
        String originalName = file.getFileName().toString();

        int totalParts;
        long[] chunkSizes;

        /* -------------------------------
           half モードは常に 2分割固定
        -------------------------------- */
        if (mode.equalsIgnoreCase("half")) {
            totalParts = 2;

            long half = totalSize / 2;
            chunkSizes = new long[]{half, totalSize - half};
        }
        else { 
            /* count モード */
            totalParts = parts;

            long base = totalSize / parts;
            long rem  = totalSize % parts;

            chunkSizes = new long[parts];
            for (int i = 0; i < parts; i++) chunkSizes[i] = base;
            chunkSizes[parts - 1] += rem;
        }

        List<Path> outList = new ArrayList<>();

        try (InputStream in = Files.newInputStream(file)) {
            for (int i = 0; i < totalParts; i++) {
                byte[] buf = in.readNBytes((int) chunkSizes[i]);

                Path out = Path.of(file.toString() + ".jdec" + i);
                writePart(out, i, totalParts, originalName, buf);
                outList.add(out);
            }
        }

        /* -------------------------------
           delmode: 元ファイル削除
        -------------------------------- */
        if (delmode) {
            Files.deleteIfExists(file);
        }

        return outList;
    }

    /* ============================================================
       part0 から自動判定
    ============================================================ */
    public static Path mergeFromPart0(Path part0) throws IOException {

        Map<String, String> cfg = loadSettings();
        boolean enabled = Boolean.parseBoolean(cfg.get("enabled"));
        if (!enabled) {
            System.out.println("分割設定が無効のため結合しません。");
            return null;
        }

        String base = part0.getFileName().toString();
        String prefix = base.substring(0, base.length() - 1); // jdec

        Path dir = part0.getParent();
        List<Path> parts = new ArrayList<>();

        try (DirectoryStream<Path> ds = Files.newDirectoryStream(dir)) {
            for (Path p : ds) {
                if (p.getFileName().toString().startsWith(prefix)) parts.add(p);
            }
        }

        return merge(parts, null);
    }

    /* ============================================================
       結合（完全署名検証）
    ============================================================ */
    public static Path merge(List<Path> parts, Path output) throws IOException {

        class Info {
            int index;
            MinimalJSONObject header;
            Path path;
        }

        List<Info> infoList = new ArrayList<>();

        for (Path p : parts) {
            try (InputStream in = Files.newInputStream(p)) {

                byte[] sizeRaw = in.readNBytes(4);
                int headerSize = ByteBuffer.wrap(sizeRaw).getInt();

                byte[] headerRaw = in.readNBytes(headerSize);
                MinimalJSONObject json =
                        new MinimalJSONObject(new String(headerRaw, StandardCharsets.UTF_8));

                Info info = new Info();
                info.index = json.getInt("part_index");
                info.header = json;
                info.path = p;
                infoList.add(info);
            }
        }

        infoList.sort(Comparator.comparingInt(o -> o.index));

        String originalName = infoList.get(0).header.getString("original_name");
        int totalParts      = infoList.get(0).header.getInt("total_parts");

        if (infoList.size() != totalParts)
            throw new RuntimeException("パート数不一致");

        if (output == null)
            output = parts.get(0).getParent().resolve(originalName);

        try (OutputStream out = Files.newOutputStream(output)) {

            for (Info info : infoList) {
                try (InputStream in = Files.newInputStream(info.path)) {

                    int headerSize = ByteBuffer.wrap(in.readNBytes(4)).getInt();
                    in.readNBytes(headerSize);

                    byte[] body = in.readAllBytes();

                    if (!sha256(body).equals(info.header.getString("sha256")))
                        throw new RuntimeException(info.path + " が改ざんされています");

                    out.write(body);
                }
            }
        }

        return output;
    }
}
