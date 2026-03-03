import java.io.IOException;
import java.nio.file.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

public final class JAESPublicKeyExporter {

    private static final Path SOURCE_PATH =
        Paths.get(System.getenv("APPDATA"), "JAES", "key", "public.pem");

    public static void exportToJarDirectory(boolean renameForExternal) throws IOException {
        if (!Files.exists(SOURCE_PATH)) {
            throw new IOException("APPDATA 内に公開鍵が見つかりません: " + SOURCE_PATH);
        }

        Path jarDir = getJarDirectory();
        Path destination;

        if (renameForExternal) {
            String timestamp = LocalDateTime.now()
                    .format(DateTimeFormatter.ofPattern("yyyyMMdd_HHmmss"));
            destination = jarDir.resolve("JAES_PublicKey_" + timestamp + ".pem");
        } else {
            destination = jarDir.resolve("public.pem");
        }

        Files.copy(SOURCE_PATH, destination, StandardCopyOption.REPLACE_EXISTING);
        System.out.println("公開鍵をエクスポートしました → " + destination.toAbsolutePath());
    }

    private static Path getJarDirectory() {
        try {
            Path jarPath = Paths.get(JAESPublicKeyExporter.class
                    .getProtectionDomain()
                    .getCodeSource()
                    .getLocation()
                    .toURI());
            return Files.isRegularFile(jarPath)
                    ? jarPath.getParent()
                    : jarPath;
        } catch (Exception e) {
            return Paths.get(".").toAbsolutePath().normalize();
        }
    }
}
