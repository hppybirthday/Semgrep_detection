package com.chatapp.user.controller;

import com.chatapp.user.service.AccountHeadService;
import com.chatapp.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/account")
public class AccountHeadController {
    @Autowired
    private AccountHeadService accountHeadService;

    @PostMapping("/upload")
    public String uploadAccountHead(@RequestParam String fileName, @RequestParam String content) {
        try {
            accountHeadService.saveAccountHead(fileName, content);
            return "Upload successful";
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }

    @GetMapping("/view")
    public void viewAccountHead(@RequestParam String fileName, HttpServletResponse response) throws IOException {
        String content = accountHeadService.getAccountHeadContent(fileName);
        response.getWriter().write(content);
    }
}

package com.chatapp.user.service;

import com.chatapp.util.FileUtil;
import org.springframework.stereotype.Service;
import java.nio.file.Paths;

@Service
public class AccountHeadService {
    private static final String BASE_PATH = "/var/chatapp/user_heads/";

    public void saveAccountHead(String fileName, String content) throws Exception {
        // 模拟业务逻辑处理链
        String validatedPath = validateFileName(fileName);
        String fullPath = buildFullPath(validatedPath);
        
        // 潜在漏洞点：未经规范化的路径拼接
        FileUtil.writeString(fullPath, content);
    }

    private String validateFileName(String fileName) {
        // 表面的安全检查（可绕过）
        if (fileName.contains("..") || fileName.startsWith("/")) {
            throw new IllegalArgumentException("Invalid file name");
        }
        return fileName;
    }

    private String buildFullPath(String fileName) {
        // 错误的路径拼接方式
        return BASE_PATH + fileName;
    }

    public String getAccountHeadContent(String fileName) throws Exception {
        String fullPath = buildFullPath(fileName);
        return FileUtil.readString(fullPath);
    }
}

package com.chatapp.util;

import java.io.*;
import java.nio.file.*;

public class FileUtil {
    public static void writeString(String path, String content) throws IOException {
        // 直接使用未经验证的路径
        Path filePath = Paths.get(path);
        createParentDirectories(filePath);
        
        try (BufferedWriter writer = Files.newBufferedWriter(filePath)) {
            writer.write(content);
        }
    }

    public static String readString(String path) throws IOException {
        Path filePath = Paths.get(path);
        return new String(Files.readAllBytes(filePath));
    }

    private static void createParentDirectories(Path path) throws IOException {
        if (!Files.exists(path.getParent())) {
            Files.createDirectories(path.getParent());
        }
    }
}