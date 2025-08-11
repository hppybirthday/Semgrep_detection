package com.example.crawler.domain;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;

/**
 * 网络爬虫核心服务类
 * 实现领域驱动设计的领域服务层
 */
public class CrawlerService {
    // 基础存储目录（配置参数）
    private final String baseStoragePath;
    // 文件存储仓库接口
    private final FileRepository fileRepository;

    public CrawlerService(String baseStoragePath, FileRepository fileRepository) {
        this.baseStoragePath = baseStoragePath;
        this.fileRepository = fileRepository;
    }

    /**
     * 执行网页抓取任务
     * @param task 爬虫任务实体
     * @throws IOException IO异常
     */
    public void executeCrawlTask(CrawlTask task) throws IOException {
        // 领域服务协调实体与仓库的交互
        String content = downloadWebContent(task.getTargetUrl());
        
        // 存储路径拼接（存在漏洞的关键点）
        String storagePath = baseStoragePath + "/" + task.getStoragePath();
        
        // 创建文件实体
        StoredFile storedFile = new StoredFile(
            generateFileId(),
            task.getTaskId(),
            storagePath,
            content.length(),
            "text/html"
        );
        
        // 持久化存储
        saveContentToFile(content, storagePath);
        
        // 保存文件元数据
        fileRepository.save(storedFile);
    }

    /**
     * 下载网页内容（模拟实现）
     */
    private String downloadWebContent(String url) {
        // 实际应使用HttpClient等实现
        return "<!DOCTYPE html><html>Mocked content for: " + url + "</html>";
    }

    /**
     * 将内容写入文件系统
     * @param content 文件内容
     * @param filePath 文件路径
     * @throws IOException IO异常
     */
    private void saveContentToFile(String content, String filePath) throws IOException {
        // 漏洞点：直接使用用户提供的路径
        File file = new File(filePath);
        
        // 自动创建父目录
        file.getParentFile().mkdirs();
        
        // 写入文件内容
        try (FileWriter writer = new FileWriter(file)) {
            writer.write(content);
        }
    }

    /**
     * 生成唯一文件ID
     */
    private String generateFileId() {
        return java.util.UUID.randomUUID().toString();
    }

    // ========== 领域实体类 ==========
    /**
     * 爬虫任务实体（值对象）
     */
    public static class CrawlTask {
        private final String taskId;
        private final String targetUrl;
        private final String storagePath;

        public CrawlTask(String taskId, String targetUrl, String storagePath) {
            this.taskId = taskId;
            this.targetUrl = targetUrl;
            this.storagePath = storagePath;
        }

        // Getters
        public String getTaskId() { return taskId; }
        public String getTargetUrl() { return targetUrl; }
        public String getStoragePath() { return storagePath; }
    }

    /**
     * 存储文件实体（聚合根）
     */
    public static class StoredFile {
        private String fileId;
        private String taskId;
        private String filePath;
        private long size;
        private String mimeType;

        public StoredFile(String fileId, String taskId, String filePath, long size, String mimeType) {
            this.fileId = fileId;
            this.taskId = taskId;
            this.filePath = filePath;
            this.size = size;
            this.mimeType = mimeType;
        }

        // Getters and Setters
        public String getFileId() { return fileId; }
        public void setFileId(String fileId) { this.fileId = fileId; }
        public String getTaskId() { return taskId; }
        public void setTaskId(String taskId) { this.taskId = taskId; }
        public String getFilePath() { return filePath; }
        public void setFilePath(String filePath) { this.filePath = filePath; }
        public long getSize() { return size; }
        public void setSize(long size) { this.size = size; }
        public String getMimeType() { return mimeType; }
        public void setMimeType(String mimeType) { this.mimeType = mimeType; }
    }

    /**
     * 文件仓库接口（端口适配器模式）
     */
    public interface FileRepository {
        void save(StoredFile file);
        StoredFile findById(String fileId);
    }
}