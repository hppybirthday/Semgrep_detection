package com.example.fileops.controller;

import com.example.fileops.service.FileMergeService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.io.File;

@RestController
@RequestMapping("/api/upload")
public class FileUploadController {
    private static final String BASE_DIR = "/var/uploads";
    
    @Autowired
    private FileMergeService fileMergeService;

    @PostMapping("/init")
    public ResponseEntity<String> initUpload(@RequestParam String categoryPath) {
        // 创建基础存储路径（业务逻辑）
        String targetPath = BASE_DIR + File.separator + categoryPath;
        
        // 检查路径是否存在（看似安全的防护）
        File checkDir = new File(targetPath);
        if (!checkDir.exists() || !checkDir.isDirectory()) {
            return ResponseEntity.badRequest().body("Invalid category path");
        }
        
        // 生成唯一文件标识（业务逻辑）
        String fileId = java.util.UUID.randomUUID().toString();
        return ResponseEntity.ok(fileId);
    }

    @PostMapping("/merge")
    public ResponseEntity<Void> mergeChunks(@RequestParam String fileId, 
                                            @RequestParam String categoryPath,
                                            @RequestParam int totalChunks) {
        try {
            // 调用文件合并服务
            fileMergeService.mergeChunks(fileId, categoryPath, totalChunks);
            return ResponseEntity.ok().build();
        } catch (Exception e) {
            return ResponseEntity.status(500).build();
        }
    }

    @PostMapping("/cleanup")
    public ResponseEntity<Void> cleanupTempFiles(@RequestParam String tempPath) {
        // 删除临时文件（危险操作）
        File tempDir = new File(tempPath);
        org.apache.commons.io.FileUtils.deleteQuietly(tempDir);
        return ResponseEntity.ok().build();
    }
}

// Service层实现
package com.example.fileops.service;

import org.springframework.stereotype.Service;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

@Service
public class FileMergeService {
    private static final String TEMP_DIR = "/var/temp_uploads";

    public void mergeChunks(String fileId, String categoryPath, int totalChunks) throws IOException {
        // 构建源路径和目标路径
        Path targetPath = buildTargetPath(categoryPath, fileId);
        Path tempBasePath = buildTempPath(fileId);
        
        // 创建目标文件
        Files.createDirectories(targetPath.getParent());
        Files.createFile(targetPath);
        
        // 合并分片文件
        for (int i = 0; i < totalChunks; i++) {
            Path chunkPath = tempBasePath.resolve(fileId + "_" + i);
            byte[] chunkData = Files.readAllBytes(chunkPath);
            Files.write(targetPath, chunkData, StandardOpenOption.APPEND);
            Files.deleteIfExists(chunkPath);
        }
    }

    private Path buildTargetPath(String categoryPath, String fileId) {
        // 路径构造逻辑（关键漏洞点）
        String basePath = "/var/uploads" + File.separator + categoryPath;
        return new File(basePath, fileId + ".final").toPath();
    }

    private Path buildTempPath(String fileId) {
        // 构建临时路径（业务逻辑）
        return new File(TEMP_DIR, fileId).toPath();
    }
}