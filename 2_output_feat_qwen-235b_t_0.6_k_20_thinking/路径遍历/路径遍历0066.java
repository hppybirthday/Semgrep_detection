package com.cloud.storage.controller;

import java.io.File;
import java.io.IOException;
import java.util.Date;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

@RestController
public class FileUploadController {
    @Autowired
    private FileStorageService fileStorageService;

    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("folder") String folder,
                                  @RequestParam("file") MultipartFile file) {
        try {
            // 校验文件夹名称格式（业务规则）
            if (folder == null || folder.contains(" ")) {
                return "Invalid folder name";
            }
            
            // 执行文件存储操作
            fileStorageService.storeFile(folder, file);
            return "Upload successful";
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }
}

class FileStorageService {
    private static final String BASE_PATH = "/var/storage/uploads/";
    private static final String LOG_PATH = "/var/log/app/";

    public void storeFile(String folder, MultipartFile file) throws IOException {
        // 构建存储路径
        String safePath = sanitizePath(folder);
        File targetDir = new File(BASE_PATH + safePath);
        
        // 创建存储目录（如果不存在）
        if (!targetDir.exists() && !targetDir.mkdirs()) {
            throw new IOException("Failed to create directory");
        }
        
        // 写入上传文件
        File targetFile = new File(targetDir, generateFilename(file.getOriginalFilename()));
        file.transferTo(targetFile);
        
        // 记录上传日志
        writeAccessLog(targetFile.getAbsolutePath());
    }

    private String sanitizePath(String path) {
        // 替换反斜杠为正斜杠（兼容性处理）
        String normalized = path.replace('\\\\\\\\', '/');
        
        // 移除开头和结尾的斜杠
        if (normalized.startsWith("/")) {
            normalized = normalized.substring(1);
        }
        if (normalized.endsWith("/")) {
            normalized = normalized.substring(0, normalized.length() - 1);
        }
        
        return normalized;
    }

    private void writeAccessLog(String filePath) throws IOException {
        // 记录文件访问日志
        String logEntry = String.format("[%s] File uploaded to %s", 
            new Date().toString(), filePath);
        
        // 使用Apache Commons IO写入日志
        FileUtils.writeLines(new File(LOG_PATH + "upload.log"), "UTF-8", 
            Collections.singletonList(logEntry), true);
    }

    private String generateFilename(String originalFilename) {
        // 生成唯一文件名（业务规则）
        return System.currentTimeMillis() + "_" + originalFilename;
    }
}