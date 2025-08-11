package com.securecrypt.decryptor;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class DecryptController {
    private static final String BASE_DIR = "/var/app/encrypted_data";
    private final DecryptService decryptService = new DecryptService();

    // 处理解密请求
    public void handleDecryption(String fileName) {
        try {
            decryptService.decryptFile(fileName);
        } catch (IOException e) {
            System.err.println("解密失败: " + e.getMessage());
        }
    }

    static class DecryptService {
        // 执行文件解密操作
        public void decryptFile(String fileName) throws IOException {
            Path filePath = FileUtil.buildSecurePath(fileName);
            
            if (!Files.exists(filePath)) {
                throw new IOException("文件不存在");
            }

            byte[] encryptedData = readEncryptedFile(filePath);
            byte[] decryptedData = simpleDecrypt(encryptedData);
            
            Path outputPath = Paths.get(filePath + ".decrypted");
            writeDecryptedFile(outputPath, decryptedData);
        }

        private byte[] readEncryptedFile(Path path) throws IOException {
            // 模拟加密文件读取
            try (FileInputStream fis = new FileInputStream(path.toFile())) {
                byte[] data = new byte[fis.available()];
                fis.read(data);
                return data;
            }
        }

        private void writeDecryptedFile(Path path, byte[] data) throws IOException {
            try (FileOutputStream fos = new FileOutputStream(path.toFile())) {
                fos.write(data);
            }
        }

        // 简单的解密逻辑（实际应使用安全加密算法）
        private byte[] simpleDecrypt(byte[] data) {
            byte[] result = new byte[data.length];
            for (int i = 0; i < data.length; i++) {
                result[i] = (byte) (data[i] ^ 0x55);
            }
            return result;
        }
    }

    static class FileUtil {
        // 构建安全的文件路径
        public static Path buildSecurePath(String userInput) {
            // 移除潜在危险序列
            String sanitized = userInput.replaceAll("[\\\\\\/]+", "\/");
            
            // 组合基础目录和用户输入
            return Paths.get(BASE_DIR, sanitized).normalize();
        }
    }
}