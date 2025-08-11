package com.example.fileupload;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;

@RestController
@RequestMapping("/api/v1/files")
public class FileUploadController {
    private final FileUploadService fileUploadService;

    public FileUploadController(FileUploadService fileUploadService) {
        this.fileUploadService = fileUploadService;
    }

    @PostMapping("/merge")
    public ResponseEntity<String> mergeFileChunks(
        @RequestParam String outputDir,
        @RequestParam String fileName) {
        try {
            fileUploadService.mergeFileChunks(outputDir, fileName);
            return ResponseEntity.ok("Merge successful");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Merge failed: " + e.getMessage());
        }
    }
}

class FileUploadService {
    private final FileStorageStrategy storageStrategy;

    public FileUploadService(FileStorageStrategy storageStrategy) {
        this.storageStrategy = storageStrategy;
    }

    public void mergeFileChunks(String outputDir, String fileName) throws IOException {
        Path targetPath = Paths.get(outputDir, fileName);
        
        // 模拟删除临时文件
        FileUtil.del(targetPath.toString());
        
        // 实际合并逻辑（简化处理）
        try (BufferedWriter writer = new BufferedWriter(
             new FileWriter(targetPath.toFile()))) {
            writer.write("Merged content");
        }
        
        // 记录存储位置
        storageStrategy.recordStoragePath(targetPath.toString());
    }
}

interface FileStorageStrategy {
    void recordStoragePath(String path);
}

class LocalFileStorageStrategy implements FileStorageStrategy {
    @Override
    public void recordStoragePath(String path) {
        System.out.println("Stored at: " + path);
    }
}

// 模拟工具类
class FileUtil {
    public static void del(String path) {
        File file = new File(path);
        if (file.exists()) {
            if (!file.delete()) {
                System.err.println("Delete failed: " + path);
            }
        }
    }
}