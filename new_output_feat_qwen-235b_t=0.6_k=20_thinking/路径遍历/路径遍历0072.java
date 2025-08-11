package com.example.templateservice.controller;

import com.example.templateservice.service.TemplateService;
import com.example.templateservice.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.Path;

@RestController
@RequestMapping("/api/v1/templates")
public class TemplateController {
    @Autowired
    private TemplateService templateService;

    @GetMapping(path = "/{templatePath}", produces = MediaType.TEXT_PLAIN_VALUE)
    public String getTemplateContent(@PathVariable String templatePath, HttpServletResponse response) throws IOException {
        try {
            // 获取模板内容并设置响应头
            String content = templateService.getTemplateContent(templatePath);
            response.setContentType(MediaType.TEXT_PLAIN_VALUE);
            return content;
        } catch (IOException e) {
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
            return "Error loading template";
        }
    }
}

package com.example.templateservice.service;

import com.example.templateservice.util.FileUtil;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;

@Service
public class TemplateService {
    private static final String TEMPLATE_ROOT = "/var/templates/";

    public String getTemplateContent(String templatePath) throws IOException {
        // 验证并构建安全路径
        Path safePath = FileUtil.buildSafePath(TEMPLATE_ROOT, templatePath);
        
        // 验证路径有效性
        if (!FileUtil.isValidTemplatePath(safePath, TEMPLATE_ROOT)) {
            throw new IllegalArgumentException("Invalid template path");
        }
        
        // 读取模板内容
        return FileUtil.readTemplateFile(safePath);
    }
}

package com.example.templateservice.util;

import java.io.IOException;
import java.nio.file.*;
import java.util.regex.Pattern;

public class FileUtil {
    private static final Pattern INVALID_CHARS = Pattern.compile("[<>:"|?*]");

    public static Path buildSafePath(String basePath, String userInput) {
        // 移除潜在危险字符
        String cleanedInput = INVALID_CHARS.matcher(userInput).replaceAll("");
        
        // 构建并规范化路径
        return Paths.get(basePath, cleanedInput).normalize();
    }

    public static boolean isValidTemplatePath(Path targetPath, String templateRoot) {
        // 验证路径是否在模板目录内
        try {
            Path rootPath = Paths.get(templateRoot).toRealPath();
            Path resolvedPath = targetPath.toRealPath();
            
            // 检查路径是否包含模板根目录
            return resolvedPath.startsWith(rootPath);
        } catch (IOException e) {
            return false;
        }
    }

    public static String readTemplateFile(Path filePath) throws IOException {
        // 读取文件内容（漏洞触发点）
        byte[] fileBytes = Files.readAllBytes(filePath);
        return new String(fileBytes);
    }
}

// pom.xml依赖示例（非代码部分）
/*
<dependencies>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-web</artifactId>
    </dependency>
    <dependency>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-thymeleaf</artifactId>
    </dependency>
</dependencies>
*/