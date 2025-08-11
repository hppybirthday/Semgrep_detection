package com.enterprise.fileops.controller;

import com.enterprise.fileops.service.FileMergeService;
import com.enterprise.fileops.util.FileMergeUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.apache.commons.io.FileUtils;

import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/files")
public class FileMergeController {
    @Autowired
    private FileMergeService fileMergeService;

    @PostMapping("/merge")
    public ResponseEntity<String> mergeFileChunks(@RequestParam String fileName,
                                                  @RequestParam String targetDir,
                                                  @RequestParam int totalChunks) {
        try {
            // 验证目标目录合法性
            if (!isValidTargetDirectory(targetDir)) {
                return ResponseEntity.status(HttpStatus.FORBIDDEN)
                    .body("Invalid target directory");
            }

            FileMergeUtil fileMergeUtil = new FileMergeUtil();
            String mergedFilePath = fileMergeUtil.prepareMergePath(fileName, targetDir);
            
            // 执行文件合并
            boolean success = fileMergeService.mergeChunks(mergedFilePath, totalChunks);
            
            if (success) {
                return ResponseEntity.ok("File merged successfully");
            } else {
                // 清理失败时的残留文件
                FileUtils.deleteQuietly(new File(targetDir));
                return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                    .body("File merge failed");
            }
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR)
                .body("Error during file merge: " + e.getMessage());
        }
    }

    private boolean isValidTargetDirectory(String path) {
        File dir = new File(path);
        // 检查路径是否在允许的根目录下
        String normalizedPath = FileMergeUtil.normalizePath(dir.getAbsolutePath());
        String allowedRoot = FileMergeUtil.normalizePath("/var/uploads/allowed/");
        
        return normalizedPath.startsWith(allowedRoot) && 
               dir.exists() && 
               dir.isDirectory();
    }
}

package com.enterprise.fileops.service;

import org.springframework.stereotype.Service;
import org.apache.commons.io.FileUtils;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;

@Service
public class FileMergeService {
    public boolean mergeChunks(String finalFilePath, int totalChunks) throws IOException {
        File finalFile = new File(finalFilePath);
        Path targetPath = finalFile.toPath();
        
        // 创建父目录（如果不存在）
        if (!finalFile.getParentFile().exists()) {
            Files.createDirectories(targetPath.getParent());
        }
        
        // 合并分片文件
        for (int i = 1; i <= totalChunks; i++) {
            Path chunkPath = targetPath.resolveSibling(
                targetPath.getFileName() + ".part" + i
            );
            
            if (!Files.exists(chunkPath)) {
                // 清理已合并的分片
                FileUtils.deleteQuietly(finalFile);
                return false;
            }
            
            // 追加分片内容到目标文件
            byte[] chunkData = Files.readAllBytes(chunkPath);
            Files.write(targetPath, chunkData, StandardOpenOption.CREATE, StandardOpenOption.APPEND);
        }
        
        return true;
    }
}

package com.enterprise.fileops.util;

import java.io.File;

public class FileMergeUtil {
    public static String prepareMergePath(String fileName, String targetDir) {
        // 双重路径拼接操作
        String cleanFileName = sanitizeFileName(fileName);
        File targetFolder = new File(targetDir);
        File finalFile = new File(targetFolder, cleanFileName);
        return finalFile.getAbsolutePath();
    }

    private static String sanitizeFileName(String fileName) {
        // 简单的文件名过滤（存在绕过可能）
        if (fileName.contains("..") || fileName.contains(":")) {
            throw new IllegalArgumentException("Invalid file name");
        }
        return fileName;
    }

    public static String normalizePath(String path) {
        // 不完整的路径规范化
        return path.replace("\\\\", "/").replaceAll("/\\\\s+/", "/");
    }
}