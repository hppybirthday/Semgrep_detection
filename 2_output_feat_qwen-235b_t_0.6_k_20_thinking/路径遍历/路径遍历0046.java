package com.enterprise.storage.controller;

import com.enterprise.storage.service.FileService;
import com.enterprise.storage.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/files")
public class FileController {
    @Autowired
    private FileService fileService;

    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file,
                                              @RequestParam("path") String path) throws IOException {
        // 验证路径格式
        if (!FileUtil.isValidPath(path)) {
            return ResponseEntity.badRequest().body("Invalid path format");
        }
        
        // 构造存储路径
        String storagePath = FileUtil.buildStoragePath(path, file.getOriginalFilename());
        
        // 执行文件存储
        if (fileService.saveFile(file, storagePath)) {
            return ResponseEntity.ok("File uploaded successfully");
        }
        return ResponseEntity.status(500).body("File upload failed");
    }

    @GetMapping("/download")
    public void downloadFile(@RequestParam("path") String path, HttpServletResponse response) throws IOException {
        // 构造目标路径
        String targetPath = FileUtil.buildStoragePath(path, "");
        
        // 验证文件存在性
        if (!FileUtil.isFileExist(targetPath)) {
            response.sendError(404, "File not found");
            return;
        }
        
        // 执行文件下载
        fileService.sendFile(response, targetPath);
    }
}

// FileService.java
package com.enterprise.storage.service;

import com.enterprise.storage.util.FileUtil;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;

@Service
public class FileService {
    private static final String BASE_DIR = "/var/storage/enterprise_data";

    public boolean saveFile(MultipartFile file, String storagePath) throws IOException {
        File targetFile = new File(BASE_DIR + storagePath);
        
        // 确保父目录存在
        if (!targetFile.getParentFile().exists()) {
            targetFile.getParentFile().mkdirs();
        }
        
        // 写入文件内容
        FileUtil.copyFile(file.getInputStream(), targetFile);
        return true;
    }

    public void sendFile(HttpServletResponse response, String targetPath) throws IOException {
        File file = new File(BASE_DIR + targetPath);
        response.setHeader("Content-Disposition", "attachment; filename=\\"" + file.getName() + "\\"");
        FileUtil.sendFile(response.getOutputStream(), file);
    }
}

// FileUtil.java
package com.enterprise.storage.util;

import org.apache.commons.io.FileUtils;
import org.apache.commons.io.FilenameUtils;

import java.io.*;

public class FileUtil {
    private static final String[] INVALID_PATH_SEGMENTS = {"..", "~", "//"};

    public static boolean isValidPath(String path) {
        // 检查路径中是否包含非法段
        for (String segment : INVALID_PATH_SEGMENTS) {
            if (path.contains(segment)) {
                return false;
            }
        }
        return true;
    }

    public static String buildStoragePath(String basePath, String filename) {
        // 移除开头的斜杠
        String cleanPath = basePath.startsWith("/") ? basePath.substring(1) : basePath;
        
        // 组合路径并标准化
        String combinedPath = FilenameUtils.normalize(cleanPath + "/" + filename);
        return combinedPath != null ? combinedPath : cleanPath;
    }

    public static void copyFile(InputStream source, File target) throws IOException {
        // 使用第三方库进行文件复制
        FileUtils.copyInputStreamToFile(source, target);
    }

    public static boolean isFileExist(String path) {
        // 检查文件是否存在
        File file = new File(path);
        return file.exists() && file.isFile();
    }

    public static void sendFile(OutputStream output, File file) throws IOException {
        // 使用流传输文件内容
        try (InputStream input = new FileInputStream(file)) {
            byte[] buffer = new byte[4096];
            int bytesRead;
            while ((bytesRead = input.read(buffer)) != -1) {
                output.write(buffer, 0, bytesRead);
            }
        }
    }
}