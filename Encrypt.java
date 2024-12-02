import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Timer;
import java.util.TimerTask;

public class Encrypt {

    private static final int KEY_SIZE = 32; // 256-bit key size
    private static final int BLOCK_SIZE = 16; // AES block size (128-bit)

    public static void main(String[] args) {
        // Display splash screen
       

        // Launch the main application after the splash screen
        SwingUtilities.invokeLater(() -> {
            JFrame frame = new JFrame("Encrypt/Decrypt File");
            frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
            frame.setSize(400, 300);
            frame.setLayout(new BorderLayout());

            JPanel panel = new JPanel();
            panel.setLayout(new GridLayout(5, 1));

            JLabel keyLabel = new JLabel("Enter key:");
            JPasswordField keyField = new JPasswordField();
            JLabel fileLabel = new JLabel("Choose a file:");
            JButton fileButton = new JButton("Browse");
            JLabel filePathLabel = new JLabel("No file selected");
            JButton encryptButton = new JButton("Encrypt");
            JButton decryptButton = new JButton("Decrypt");

            panel.add(keyLabel);
            panel.add(keyField);
            panel.add(fileLabel);
            panel.add(fileButton);
            panel.add(filePathLabel);

            JPanel buttonPanel = new JPanel();
            buttonPanel.setLayout(new FlowLayout());
            buttonPanel.add(encryptButton);
            buttonPanel.add(decryptButton);

            frame.add(panel, BorderLayout.CENTER);
            frame.add(buttonPanel, BorderLayout.SOUTH);

            final File[] selectedFile = {null};

            fileButton.addActionListener(e -> {
                JFileChooser fileChooser = new JFileChooser();
                int returnValue = fileChooser.showOpenDialog(frame);
                if (returnValue == JFileChooser.APPROVE_OPTION) {
                    selectedFile[0] = fileChooser.getSelectedFile();
                    filePathLabel.setText(selectedFile[0].getAbsolutePath());
                }
            });

            encryptButton.addActionListener(e -> {
                String key = new String(keyField.getPassword());
                if (selectedFile[0] == null || key.isEmpty()) {
                    JOptionPane.showMessageDialog(frame, "Please select a file and enter a key.");
                    return;
                }
                try {
                    encryptFile(selectedFile[0].getAbsolutePath(), key.getBytes());
                    JOptionPane.showMessageDialog(frame, "Encryption successful! File saved as: " + selectedFile[0].getAbsolutePath() + ".enc");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(frame, "Encryption failed: " + ex.getMessage());
                }
            });

            decryptButton.addActionListener(e -> {
                String key = new String(keyField.getPassword());
                if (selectedFile[0] == null || key.isEmpty()) {
                    JOptionPane.showMessageDialog(frame, "Please select a file and enter a key.");
                    return;
                }
                try {
                    decryptFile(selectedFile[0].getAbsolutePath(), key.getBytes());
                    JOptionPane.showMessageDialog(frame, "Decryption successful! File saved.");
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(frame, "Decryption failed: " + ex.getMessage());
                }
            });

            frame.setVisible(true);
        });
    }

    public static void encryptFile(String inputFile, byte[] key) throws Exception {
        byte[] paddedKey = padKey(key);
        byte[] iv = new byte[BLOCK_SIZE];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        SecretKeySpec secretKey = new SecretKeySpec(paddedKey, "AES");
        IvParameterSpec ivParams = new IvParameterSpec(iv);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey, ivParams);

        byte[] fileData;
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            fileData = readAllBytes(fis);
        }

        byte[] encryptedData = cipher.doFinal(fileData);

        try (FileOutputStream fos = new FileOutputStream(inputFile + ".enc")) {
            fos.write(iv);
            fos.write(encryptedData);
        }
    }

    public static void decryptFile(String inputFile, byte[] key) throws Exception {
        try (FileInputStream fis = new FileInputStream(inputFile)) {
            byte[] iv = new byte[BLOCK_SIZE];
            fis.read(iv);

            byte[] fileData = readAllBytes(fis);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            SecretKeySpec secretKey = new SecretKeySpec(padKey(key), "AES");
            IvParameterSpec ivParams = new IvParameterSpec(iv);
            cipher.init(Cipher.DECRYPT_MODE, secretKey, ivParams);

            byte[] decryptedData = cipher.doFinal(fileData);

            String outputFile = inputFile.replace(".enc", "");
            try (FileOutputStream fos = new FileOutputStream(outputFile)) {
                fos.write(decryptedData);
            }
        }
    }

    public static byte[] padKey(byte[] key) {
        if (key.length >= KEY_SIZE) {
            return Arrays.copyOf(key, KEY_SIZE);
        }
        byte[] paddedKey = new byte[KEY_SIZE];
        System.arraycopy(key, 0, paddedKey, 0, key.length);
        return paddedKey;
    }

    public static byte[] readAllBytes(FileInputStream fis) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] temp = new byte[1024];
        int bytesRead;
        while ((bytesRead = fis.read(temp)) != -1) {
            buffer.write(temp, 0, bytesRead);
        }
        return buffer.toByteArray();
    }
}
