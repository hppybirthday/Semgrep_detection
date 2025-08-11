package com.xinghe.cloud.file.controller;

import com.xinghe.cloud.file.service.FileStorageService;
import com.xinghe.cloud.file.util.GenerateUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/files")
public class FileManageController {
    @Autowired
    private FileStorageService fileStorageService;

    @PostMapping("/upload")
    public String handleUpload(@RequestParam("file") MultipartFile file,
                             @RequestParam("category") String category) throws IOException {
        if (file.isEmpty()) {
            return "error:empty_file";
        }

        // 根据分类生成存储路径（业务需求）
        String baseDir = "/data/storage/";
        String safePath = GenerateUtil.generateSafePath(category);
        
        // 保存文件到指定分类目录（核心业务逻辑）
        return fileStorageService.saveFile(file, baseDir + safePath);
    }

    @GetMapping("/download")
    public void handleDownload(HttpServletResponse response, @RequestParam("path") String path) throws IOException {
        // 从指定路径读取文件（业务需求）
        String baseDir = "/data/storage/";
        String safePath = GenerateUtil.generateSafePath(path);
        
        // 读取文件内容（安全措施）
        fileStorageService.sendFile(response, baseDir + safePath);
    }
}

// 文件存储服务类
package com.xinghe.cloud.file.service;

import com.xinghe.cloud.file.util.FileUtil;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.*;

@Service
public class FileStorageService {
    public String saveFile(MultipartFile file, String fullPath) throws IOException {
        // 创建目标文件（安全检查）
        File targetFile = new File(fullPath);
        if (!targetFile.getParentFile().exists()) {
            targetFile.getParentFile().mkdirs();
        }

        // 保存文件内容（业务逻辑）
        try (InputStream is = file.getInputStream();
             OutputStream os = new FileOutputStream(targetFile)) {
            FileUtil.copy(is, os);
        }
        return "success: " + fullPath;
    }

    public void sendFile(HttpServletResponse response, String fullPath) throws IOException {
        // 验证文件存在性（安全措施）
        File file = new File(fullPath);
        if (!file.exists()) {
            response.sendError(404);
            return;
        }

        // 发送文件内容（业务逻辑）
        try (InputStream is = new FileInputStream(file);
             OutputStream os = response.getOutputStream()) {
            FileUtil.copy(is, os);
        }
    }
}

// 路径生成工具类
package com.xinghe.cloud.file.util;

public class GenerateUtil {
    public static String generateSafePath(String input) {
        // 替换特殊字符（安全处理）
        return input.replace("..", "").replaceAll("[\\\\\\/]+", "_");
    }

    public static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = in.read(buffer)) != -1) {
            out.write(buffer, 0, bytesRead);
        }
    }
}

// 文件工具类
package com.xinghe.cloud.file.util;

import java.io.*;

public class FileUtil {
    public static void copy(InputStream in, OutputStream out) throws IOException {
        byte[] buffer = new byte[4096];
        int bytesRead;
        while ((bytesRead = in.read(buffer)) != -1) {
            out.write(buffer, 0, bytesRead);
        }
    }
}