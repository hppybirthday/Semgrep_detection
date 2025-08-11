package com.example.vulnerable.storage;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.UUID;

/**
 * 云存储配置信息
 */
public class CloudStorageConfig {
    // 基础存储目录（模拟受限目录）
    private String baseDirectory = "/var/www/uploads/";
    
    public String getBaseDirectory() {
        return baseDirectory;
    }
}

/**
 * 抽象云存储服务
 */
public abstract class AbstractCloudStorageService {
    protected CloudStorageConfig config = new CloudStorageConfig();
    
    /**
     * 下载文件抽象方法
     * @param filePath 用户指定的文件路径
     * @return 文件字节流
     * @throws IOException
     */
    public abstract byte[] downloadFile(String filePath) throws IOException;
    
    /**
     * 生成唯一文件名
     */
    protected String generateUniqueName(String originalName) {
        return UUID.randomUUID() + "_" + originalName;
    }
}

/**
 * 本地文件存储实现（存在漏洞）
 */
public class LocalFileStorageService extends AbstractCloudStorageService {
    @Override
    public byte[] downloadFile(String filePath) throws IOException {
        // 漏洞点：直接拼接用户输入路径
        File file = new File(config.getBaseDirectory() + filePath);
        
        // 模拟文件读取
        if (!file.exists()) {
            throw new IOException("File not found");
        }
        
        // 返回文件内容（实际场景可能返回流）
        return Files.readAllBytes(file.toPath());
    }
}

/**
 * 文件控制器（REST API入口）
 */
public class FileController {
    private AbstractCloudStorageService storageService = new LocalFileStorageService();
    
    // 模拟REST API端点
    public void handleDownload(String userInputPath) {
        try {
            // 直接使用用户输入路径
            byte[] content = storageService.downloadFile(userInputPath);
            System.out.println("File content size: " + content.length);
        } catch (IOException e) {
            System.err.println("Error: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        FileController controller = new FileController();
        // 模拟攻击请求
        controller.handleDownload("../../../../etc/passwd");
    }
}