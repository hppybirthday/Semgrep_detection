package com.example.app.template;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;

@Controller
public class TemplateController {
    @Autowired
    private TemplateService templateService;

    @GetMapping("/render")
    public @ResponseBody byte[] renderTemplate(
        @RequestParam String prefix,
        @RequestParam String suffix) throws IOException {
        
        // 构建模板路径片段（业务规则：固定前缀+用户自定义路径）
        String templatePath = "templates/" + prefix + "/config/" + suffix;
        
        // 记录模板访问日志（模拟审计需求）
        TemplateLogger.logAccess(templatePath);
        
        // 获取模板内容并返回
        return templateService.getTemplateContent(templatePath);
    }
}

class TemplateLogger {
    static void logAccess(String path) {
        // 模拟日志记录（包含路径信息）
        System.out.println("[TemplateAccess] Path: " + path);
    }
}

class TemplateService {
    
    // 获取模板内容（含安全校验）
    byte[] getTemplateContent(String templatePath) throws IOException {
        if (!validateTemplatePath(templatePath)) {
            throw new IllegalArgumentException("Invalid template path");
        }
        
        // 调用底层文件读取
        return FileUtil.readTemplateFile(templatePath);
    }
    
    // 路径校验逻辑（防御措施）
    private boolean validateTemplatePath(String path) {
        // 检查路径是否包含非法字符（模拟安全措施）
        if (path.contains("..") || path.contains("~")) {
            return false;
        }
        
        // 检查路径深度（业务规则）
        String[] segments = path.split("[/\\\\\\\\]");
        return segments.length >= 3 && segments.length <= 5;
    }
}

class FileUtil {
    
    // 读取模板文件内容（核心文件操作）
    static byte[] readTemplateFile(String templatePath) throws IOException {
        java.nio.file.Path filePath = java.nio.file.Paths.get(templatePath);
        // 直接读取文件内容（存在路径遍历风险）
        return java.nio.file.Files.readAllBytes(filePath);
    }
}