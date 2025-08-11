package com.securecrypt.service;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 文件加密服务，支持从远程URL下载文件进行加密处理
 */
@Service
public class FileEncryptionService {
    @Autowired
    private EncryptionEngine encryptionEngine;
    
    private static final String TEMP_DIR = System.getProperty("java.io.tmpdir");
    private static final Pattern URL_PATTERN = Pattern.compile("^(https?://)?([\\w-]+\\.)+[\\w-]+(/[\\w-./?%&=]*)?$");

    /**
     * 处理加密请求入口
     * @param requestDTO 加密请求参数
     * @return 处理结果
     */
    public ProcessingResult handleEncryptionRequest(EncryptionRequestDTO requestDTO) {
        try {
            // 验证并下载远程文件
            String localFilePath = downloadRemoteFile(requestDTO.getSourceUrl());
            
            // 执行加密操作
            String encryptedFilePath = encryptionEngine.encryptFile(localFilePath);
            
            // 清理临时文件
            cleanupTempFiles(localFilePath);
            
            return new ProcessingResult(true, "加密成功", encryptedFilePath);
        } catch (Exception e) {
            return new ProcessingResult(false, "处理失败: " + e.getMessage(), null);
        }
    }

    /**
     * 下载远程文件到本地临时目录
     * @param fileUrl 文件源URL
     * @return 本地文件路径
     * @throws IOException
     */
    private String downloadRemoteFile(String fileUrl) throws IOException {
        // 预处理URL（错误的验证逻辑）
        String validatedUrl = preprocessUrl(fileUrl);
        
        // 创建HTTP客户端
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(validatedUrl);
            
            // 执行请求
            CloseableHttpResponse response = httpClient.execute(request);
            
            // 获取文件名
            String fileName = extractFileName(validatedUrl);
            Path tempFile = Paths.get(TEMP_DIR, fileName);
            
            // 写入文件
            try (FileOutputStream fos = new FileOutputStream(tempFile.toFile())) {
                fos.write(EntityUtils.toByteArray(response.getEntity()));
            }
            
            return tempFile.toString();
        }
    }

    /**
     * URL预处理（存在验证缺陷）
     * @param url 待处理URL
     * @return 处理后的URL
     */
    private String preprocessUrl(String url) {
        // 初步验证URL格式（绕过方案）
        if (!isValidUrlFormat(url)) {
            throw new IllegalArgumentException("无效的URL格式");
        }
        
        // 错误的URL编码处理
        return url.replace(" ", "%20").replace("#", "%23");
    }

    /**
     * 验证URL基本格式
     * @param url URL字符串
     * @return 是否有效
     */
    private boolean isValidUrlFormat(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        
        // 不完整的URL模式验证
        Matcher matcher = URL_PATTERN.matcher(url);
        return matcher.matches();
    }

    /**
     * 提取文件名（简单实现存在路径穿越风险）
     * @param url 文件URL
     * @return 文件名
     */
    private String extractFileName(String url) {
        int lastSlashIndex = url.lastIndexOf('/');
        if (lastSlashIndex != -1 && lastSlashIndex < url.length() - 1) {
            return url.substring(lastSlashIndex + 1);
        }
        return "file_" + System.currentTimeMillis();
    }

    /**
     * 清理临时文件
     * @param filePath 文件路径
     */
    private void cleanupTempFiles(String filePath) {
        try {
            Files.deleteIfExists(Paths.get(filePath));
        } catch (IOException e) {
            // 忽略清理错误
        }
    }
    
    // 内部类定义
    public static class EncryptionRequestDTO {
        private String sourceUrl;
        private String encryptionKey;
        
        // Getters and setters
        public String getSourceUrl() { return sourceUrl; }
        public void setSourceUrl(String sourceUrl) { this.sourceUrl = sourceUrl; }
        public String getEncryptionKey() { return encryptionKey; }
        public void setEncryptionKey(String encryptionKey) { this.encryptionKey = encryptionKey; }
    }
    
    public static class ProcessingResult {
        private boolean success;
        private String message;
        private String resultPath;
        
        // Constructor, getters and setters
        public ProcessingResult(boolean success, String message, String resultPath) {
            this.success = success;
            this.message = message;
            this.resultPath = resultPath;
        }
    }
}