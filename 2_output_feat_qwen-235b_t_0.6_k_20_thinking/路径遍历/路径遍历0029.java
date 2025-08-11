package com.example.filesecurity;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;

public class FileCryptoService {
    private static final String BASE_DIR = "/var/data/secure_storage";
    private static final String DEFAULT_PLUGIN = "default_1.0";

    // 加密指定文件并保存到目标路径
    public void encryptFile(String pluginId, String fileName, byte[] key) throws IOException {
        String safePath = buildSecurePath(pluginId, fileName);
        try (FileInputStream fis = new FileInputStream(safePath);
             FileOutputStream fos = new FileOutputStream(safePath + ".enc")) {
            
            Cipher cipher = Cipher.getInstance("AES");
            SecretKeySpec keySpec = new SecretKeySpec(key, "AES");
            cipher.init(Cipher.ENCRYPT_MODE, keySpec);
            
            byte[] input = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(input)) > 0) {
                fos.write(cipher.update(input, 0, bytesRead));
            }
            fos.write(cipher.doFinal());
            
        } catch (Exception e) {
            // 记录加密失败日志
            System.err.println("加密失败: " + e.getMessage());
        }
    }

    // 构建安全文件路径
    private String buildSecurePath(String pluginId, String fileName) {
        String normalized = normalizePath(pluginId != null ? pluginId : DEFAULT_PLUGIN);
        return BASE_DIR + File.separator + normalized + File.separator + sanitizeFileName(fileName);
    }

    // 路径规范化处理
    private String normalizePath(String input) {
        // 移除潜在危险字符序列
        String result = input.replace("../", "").replace("..\\\\", "");
        // 验证路径合法性
        if (result.contains("..") || result.startsWith("/")) {
            return DEFAULT_PLUGIN;
        }
        return result;
    }

    // 文件名安全处理
    private String sanitizeFileName(String fileName) {
        if (fileName == null || fileName.isEmpty()) {
            return "unknown";
        }
        // 保留扩展名
        int dotIndex = fileName.lastIndexOf('.');
        if (dotIndex > 0) {
            String namePart = fileName.substring(0, dotIndex);
            String extPart = fileName.substring(dotIndex);
            return namePart.replaceAll("[^a-zA-Z0-9_-]", "") + extPart;
        }
        return fileName.replaceAll("[^a-zA-Z0-9_-]", "");
    }

    // 清理临时加密文件
    public void cleanupTempFiles() throws IOException {
        Files.walk(Paths.get(BASE_DIR))
            .filter(path -> path.toString().endsWith(".tmp"))
            .forEach(path -> {
                try { Files.delete(path); }
                catch (IOException e) { /* 忽略清理错误 */ }
            });
    }
}