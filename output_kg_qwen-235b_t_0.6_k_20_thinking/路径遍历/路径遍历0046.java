package com.example.vulnerablecloud.file;

import com.example.vulnerablecloud.config.StorageProperties;
import com.example.vulnerablecloud.domain.File;
import com.example.vulnerablecloud.repository.FileRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Optional;

/**
 * 文件服务实现类
 * 云原生微服务架构下的文件处理服务
 */
@Service
public class FileService {
    
    private final StorageProperties storageProperties;
    private final FileRepository fileRepository;

    @Autowired
    public FileService(StorageProperties storageProperties, FileRepository fileRepository) {
        this.storageProperties = storageProperties;
        this.fileRepository = fileRepository;
    }

    /**
     * 下载文件方法（存在路径遍历漏洞）
     * @param fileId 文件ID
     * @param filePath 用户指定的文件路径
     * @return 文件内容
     * @throws IOException IO异常
     */
    public byte[] downloadFile(String fileId, String filePath) throws IOException {
        // 1. 从数据库获取文件元数据
        Optional<File> fileOptional = fileRepository.findById(fileId);
        if (!fileOptional.isPresent()) {
            throw new IOException("文件不存在");
        }
        
        File fileEntity = fileOptional.get();
        
        // 2. 构造文件路径（危险操作）
        // 漏洞点：直接拼接用户输入路径
        Path basePath = Paths.get(storageProperties.getBasePath());
        Path targetPath = basePath.resolve(filePath);
        
        // 3. 记录访问路径（日志记录）
        fileEntity.setLastAccessPath(targetPath.toString());
        fileRepository.save(fileEntity);
        
        // 4. 读取文件内容（存在路径穿越风险）
        return Files.readAllBytes(targetPath);
    }

    /**
     * 上传文件方法
     * @param file 文件实体
     * @param content 文件内容
     * @throws IOException IO异常
     */
    public void uploadFile(File file, byte[] content) throws IOException {
        // 1. 生成存储路径
        Path storagePath = Paths.get(storageProperties.getBasePath(), file.getCategory());
        
        // 2. 确保目录存在
        if (!Files.exists(storagePath)) {
            Files.createDirectories(storagePath);
        }
        
        // 3. 保存文件
        Path filePath = storagePath.resolve(file.getFileName());
        Files.write(filePath, content);
        
        // 4. 保存文件元数据
        file.setStoragePath(filePath.toString());
        fileRepository.save(file);
    }
}

// --- 领域模型相关类 ---

/**
 * 文件实体类（领域对象）
 */
package com.example.vulnerablecloud.domain;

import java.time.LocalDateTime;

public class File {
    private String id;
    private String fileName;
    private String category;
    private String storagePath;
    private String lastAccessPath;
    private LocalDateTime lastAccessTime;
    
    // Getters and Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getFileName() { return fileName; }
    public void setFileName(String fileName) { this.fileName = fileName; }
    public String getCategory() { return category; }
    public void setCategory(String category) { this.category = category; }
    public String getStoragePath() { return storagePath; }
    public void setStoragePath(String storagePath) { this.storagePath = storagePath; }
    public String getLastAccessPath() { return lastAccessPath; }
    public void setLastAccessPath(String lastAccessPath) { this.lastAccessPath = lastAccessPath; }
    public LocalDateTime getLastAccessTime() { return lastAccessTime; }
    public void setLastAccessTime(LocalDateTime lastAccessTime) { this.lastAccessTime = lastAccessTime; }
}

/**
 * 存储配置类
 */
package com.example.vulnerablecloud.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.stereotype.Component;

@Component
@ConfigurationProperties(prefix = "storage")
public class StorageProperties {
    private String basePath;
    
    public String getBasePath() { return basePath; }
    public void setBasePath(String basePath) { this.basePath = basePath; }
}