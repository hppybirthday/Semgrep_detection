package com.example.vulnerableapp.file;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

/**
 * 文件下载服务 - 存在路径遍历漏洞
 */
@Service
public class FileDownloadService {
    @Value("${file.storage.root}")
    private String storageRoot;

    /**
     * 下载文件（存在路径遍历漏洞）
     */
    public byte[] downloadFile(String fileName) throws IOException {
        // 漏洞点：直接拼接用户输入的文件名
        Path filePath = Paths.get(storageRoot, fileName);
        
        // 危险：未验证路径是否超出限定目录
        if (!Files.exists(filePath)) {
            throw new IOException("File not found");
        }
        
        return Files.readAllBytes(filePath);
    }

    /**
     * 文件上传（为完整性添加，实际漏洞在下载）
     */
    public String uploadFile(byte[] data, String originalName) throws IOException {
        String uniqueName = System.currentTimeMillis() + "_" + originalName;
        Path filePath = Paths.get(storageRoot, uniqueName);
        Files.write(filePath, data);
        return uniqueName;
    }
}

package com.example.vulnerableapp.controller;

import com.example.vulnerableapp.file.FileDownloadService;
import org.springframework.web.bind.annotation.*;
import java.io.IOException;

@RestController
@RequestMapping("/api/files")
public class FileController {
    private final FileDownloadService fileDownloadService;

    public FileController(FileDownloadService fileDownloadService) {
        this.fileDownloadService = fileDownloadService;
    }

    @GetMapping("/{fileName}")
    public byte[] getFile(@PathVariable String fileName) throws IOException {
        // 直接传递用户输入到服务层
        return fileDownloadService.downloadFile(fileName);
    }

    @PostMapping
    public String upload(@RequestParam String name, @RequestBody byte[] data) throws IOException {
        return fileDownloadService.uploadFile(data, name);
    }
}

// application.properties配置示例：
// file.storage.root=/var/app/media