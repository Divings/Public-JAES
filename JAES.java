/*
 * JAES.java - A simple AES file encryptor/decryptor GUI
 * 
 * Copyright (c) 2025 innovation craft Inc.
 *
 * This software is released under the MIT License.
 * https://opensource.org/licenses/MIT
 */
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import java.awt.*;
import java.io.*;
import java.security.SecureRandom;
import java.util.Arrays;
import java.awt.dnd.*; 
import java.awt.datatransfer.*;
import java.util.*;

public class JAES {

    private static final int KEY_SIZE = 32; // 256-bit key size
    private static final int BLOCK_SIZE = 16; // AES block size (128-bit)

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> createAndShowGUI());
    }
public static byte[] readAllBytes(InputStream inputStream) throws IOException {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] temp = new byte[1024]; 
        int bytesRead;
        while ((bytesRead = inputStream.read(temp)) != -1) {
            buffer.write(temp, 0, bytesRead);
        }
        return buffer.toByteArray();
    }

    private static void createAndShowGUI() {
        JFrame frame = new JFrame("File Encryptor/Decryptor");
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        frame.setSize(500, 400);
        frame.setLayout(new BorderLayout());

        // Header
        JLabel headerLabel = new JLabel("File Encryptor & Decryptor", JLabel.CENTER);
        headerLabel.setFont(new Font("Arial", Font.BOLD, 20));
        frame.add(headerLabel, BorderLayout.NORTH);

        // Main Panel
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new GridLayout(6, 1, 10, 10));

        JLabel instructionLabel = new JLabel("1. Select a file and enter a key to encrypt or decrypt.");
        JLabel keyLabel = new JLabel("Enter Key:");
        JPasswordField keyField = new JPasswordField();

        JLabel filePathLabel = new JLabel("No file selected");
        JButton fileButton = new JButton("Select File");

        mainPanel.add(instructionLabel);
        mainPanel.add(fileButton);
        mainPanel.add(filePathLabel);
        mainPanel.add(keyLabel);
        mainPanel.add(keyField);

        // Action Buttons
        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new FlowLayout());
        JButton encryptButton = new JButton("Encrypt");
        JButton decryptButton = new JButton("Decrypt");

        encryptButton.setBackground(Color.GREEN);
        decryptButton.setBackground(Color.ORANGE);

        buttonPanel.add(encryptButton);
        buttonPanel.add(decryptButton);

        frame.add(mainPanel, BorderLayout.CENTER);
        frame.add(buttonPanel, BorderLayout.SOUTH);

        final File[] selectedFile = {null};

new DropTarget(mainPanel, new DropTargetListener() {
            @Override
            public void dragEnter(DropTargetDragEvent dtde) { }

            @Override
            public void dragOver(DropTargetDragEvent dtde) { }

            @Override
            public void dropActionChanged(DropTargetDragEvent dtde) { }

            @Override
            public void dragExit(DropTargetEvent dte) { }

            @Override
            public void drop(DropTargetDropEvent dtde) {
                try {
                    dtde.acceptDrop(DnDConstants.ACTION_COPY);
                    Transferable transferable = dtde.getTransferable();
                    
                    Object data = transferable.getTransferData(DataFlavor.javaFileListFlavor);
                    if (data instanceof java.util.List) {
                        Iterator iterator = ((java.util.List) data).iterator();
                        if (iterator.hasNext()) {
                            selectedFile[0] = (File) iterator.next();
                            filePathLabel.setText("Selected: " + selectedFile[0].getAbsolutePath());
                        }
                    }
                } catch (Exception ex) {
                    JOptionPane.showMessageDialog(frame, "Failed to load file: " + ex.getMessage());
                }
            }
        });

       

        fileButton.addActionListener(e -> {
            JFileChooser fileChooser = new JFileChooser();
            int returnValue = fileChooser.showOpenDialog(frame);
            if (returnValue == JFileChooser.APPROVE_OPTION) {
                selectedFile[0] = fileChooser.getSelectedFile();
                filePathLabel.setText("Selected: " + selectedFile[0].getName());
            }
        });

        encryptButton.addActionListener(e -> handleFileOperation(selectedFile[0], keyField, true, frame));
        decryptButton.addActionListener(e -> handleFileOperation(selectedFile[0], keyField, false, frame));

        frame.setVisible(true);
    }

    private static void handleFileOperation(File file, JPasswordField keyField, boolean encrypt, JFrame frame) {
        if (file == null) {
            JOptionPane.showMessageDialog(frame, "No file selected. Please choose a file first.");
            return;
        }

        String key = new String(keyField.getPassword());
        if (key.isEmpty()) {
            JOptionPane.showMessageDialog(frame, "Key field cannot be empty.");
            return;
        }

        try {
            if (encrypt) {
                encryptFile(file.getAbsolutePath(), key.getBytes());
                JOptionPane.showMessageDialog(frame, "File encrypted successfully!");
            } else {
                decryptFile(file.getAbsolutePath(), key.getBytes());
                JOptionPane.showMessageDialog(frame, "File decrypted successfully!");
            }
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(frame, "Operation failed: " + ex.getMessage());
        }
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
}
