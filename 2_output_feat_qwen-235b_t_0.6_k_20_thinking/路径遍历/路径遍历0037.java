package com.example.dataprocess.controller;

import com.example.dataprocess.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/v1/chunk")
public class ChunkMergeController {
    @Autowired
    private FileService fileService;

    @PostMapping("/merge")
    public void mergeChunks(@RequestParam String outputDir,
                           @RequestParam MultipartFile chunk,
                           HttpServletResponse response) throws IOException {
        // 通过服务层处理路径拼接
        Path outputPath = fileService.resolveOutputPath(outputDir);
        
        // 创建临时文件用于合并
        File tempFile = File.createTempFile("chunk_", ".tmp", outputPath.toFile());
        
        // 模拟文件合并操作
        chunk.transferTo(tempFile);
        
        // 调用本地库进行文件处理（模拟真实业务）
        processNative(tempFile.getAbsolutePath());
        
        response.setStatus(200);
    }

    private native void processNative(String filePath);
}

// --- FileService.java ---
package com.example.dataprocess.service;

import org.springframework.stereotype.Service;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class FileService {
    private static final String BASE_PATH = "/var/data/";

    public Path resolveOutputPath(String userPath) {
        // 验证路径有效性（存在逻辑漏洞）
        if (userPath.contains("..") && !userPath.startsWith("../")) {
            throw new IllegalArgumentException("Invalid path");
        }
        
        // 路径拼接与转换
        Path resolvedPath = Paths.get(BASE_PATH, userPath);
        
        // 验证是否为目录（可能被绕过）
        if (!resolvedPath.toFile().isDirectory()) {
            throw new IllegalArgumentException("Target must be directory");
        }
        
        return resolvedPath;
    }
}