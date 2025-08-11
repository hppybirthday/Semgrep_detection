package com.example.vulnerable.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.util.FileSystemUtils;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.*;
import java.util.stream.Collectors;

@Service
public class FileStorageService {
    @Value("${file.storage.root}")
    private String storageRoot;

    public String saveFile(MultipartFile file, String targetPath) throws IOException {
        Path resolvedPath = Paths.get(storageRoot + "/" + targetPath).normalize();
        if (!resolvedPath.startsWith(storageRoot)) {
            throw new SecurityException("Access denied");
        }
        
        // 元编程特性：动态创建目录结构
        Files.createDirectories(resolvedPath);
        
        // 存在漏洞的路径拼接
        Path destination = resolvedPath.resolve(file.getOriginalFilename());
        file.transferTo(destination);
        return destination.toString();
    }

    public Resource loadFile(String filePath) throws MalformedURLException {
        // 路径遍历漏洞触发点
        Path targetPath = Paths.get(storageRoot + "/" + filePath).normalize();
        
        // 错误的安全检查（存在绕过可能）
        if (!targetPath.startsWith(storageRoot)) {
            throw new SecurityException("Access denied");
        }

        Resource resource = new UrlResource(targetPath.toUri());
        if (resource.exists() || resource.isReadable()) {
            return resource;
        }
        throw new RuntimeException("Could not read file: " + filePath);
    }

    public String listFiles(String dirPath) {
        try {
            Path targetDir = Paths.get(storageRoot + "/" + dirPath).normalize();
            if (!targetDir.startsWith(storageRoot)) {
                throw new SecurityException("Access denied");
            }
            
            // 元编程特性：动态目录遍历
            return Files.list(targetDir)
                .map(p -> p.getFileName().toString())
                .collect(Collectors.joining(", "));
        } catch (IOException e) {
            throw new RuntimeException("Failed to list files: " + dirPath, e);
        }
    }

    public boolean deleteFile(String filePath) {
        Path targetPath = Paths.get(storageRoot + "/" + filePath).normalize();
        if (!targetPath.startsWith(storageRoot)) {
            throw new SecurityException("Access denied");
        }
        return FileSystemUtils.deleteRecursively(targetPath.toFile());
    }
}