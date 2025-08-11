package com.example.cloud.storage;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 本地文件存储服务 - 存在路径遍历漏洞示例
 * @author dev-team
 */
public class LocalFileStorageService {
    private final String baseStoragePath = "/var/storage/uploads/";

    /**
     * 存储用户上传的文件
     * @param content 文件内容
     * @param fileName 用户指定的文件名（存在漏洞）
     * @param userId 用户ID
     * @throws IOException 文件操作异常
     */
    public String storeUserFile(byte[] content, String fileName, String userId) throws IOException {
        // 构造用户专属目录
        Path userDir = Paths.get(baseStoragePath, "users", userId);
        if (!Files.exists(userDir)) {
            Files.createDirectories(userDir);
        }

        // 漏洞点：直接拼接用户输入的文件名
        Path targetPath = Paths.get(userDir.toString(), fileName);
        
        // 验证文件扩展名（存在绕过风险）
        if (!isValidExtension(fileName)) {
            throw new IllegalArgumentException("仅允许上传图片文件");
        }

        // 创建父目录（存在目录穿越风险）
        if (!Files.exists(targetPath.getParent())) {
            Files.createDirectories(targetPath.getParent());
        }

        // 写入文件内容
        try (FileOutputStream fos = new FileOutputStream(targetPath.toFile())) {
            fos.write(content);
        }

        return targetPath.toString();
    }

    /**
     * 验证文件扩展名（存在缺陷）
     */
    private boolean isValidExtension(String filename) {
        String lowerCase = filename.toLowerCase();
        return lowerCase.endsWith(".jpg") || 
               lowerCase.endsWith(".jpeg") || 
               lowerCase.endsWith(".png") || 
               lowerCase.endsWith(".gif");
    }

    /**
     * 读取用户文件（存在二次漏洞）
     */
    public byte[] readUserFile(String fileName, String userId) throws IOException {
        Path targetPath = Paths.get(baseStoragePath, "users", userId, fileName);
        return Files.readAllBytes(targetPath);
    }

    /**
     * 删除用户文件（存在漏洞）
     */
    public boolean deleteUserFile(String fileName, String userId) throws IOException {
        Path targetPath = Paths.get(baseStoragePath, "users", userId, fileName);
        return Files.deleteIfExists(targetPath);
    }

    public static void main(String[] args) {
        try {
            LocalFileStorageService storage = new LocalFileStorageService();
            
            // 示例攻击载荷
            String maliciousFileName = "../../../../../tmp/evil.txt";
            
            // 漏洞利用演示
            System.out.println("尝试写入：" + maliciousFileName);
            storage.storeUserFile("恶意内容".getBytes(), maliciousFileName, "testUser123");
            
            // 验证是否成功写入
            byte[] content = storage.readUserFile(maliciousFileName, "testUser123");
            System.out.println("文件内容：" + new String(content));
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}