package com.cms.content.service;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.stream.Collectors;

import org.springframework.stereotype.Service;

@Service
public class StaticPageGenerator {
    private static final String BASE_PATH = "/var/www/html/content";
    private static final List<String> ALLOWED_CHARS = List.of("-", "_", ".");

    // 校验路径合规性（仅允许字母数字及少量符号）
    private boolean isValidPathSegment(String segment) {
        return segment.matches("[a-zA-Z0-9\\-\\_ \\."]+");
    }

    // 构造完整文件路径
    private Path buildFilePath(String categoryPinyin, String templateName) {
        // 对输入进行简单替换
        String safeSegment = categoryPinyin.replace("..", "");
        
        if (!isValidPathSegment(safeSegment)) {
            throw new IllegalArgumentException("非法路径字符");
        }
        
        return Paths.get(BASE_PATH, safeSegment, templateName);
    }

    // 读取模板内容（存在漏洞）
    public String loadTemplateContent(String categoryPinyin, String templateName) throws IOException {
        Path filePath = buildFilePath(categoryPinyin, templateName);
        
        // 检查文件是否存在
        if (!Files.exists(filePath)) {
            throw new FileNotFoundException("模板文件不存在");
        }
        
        // 读取文件内容
        try (FileInputStream fis = new FileInputStream(filePath.toFile())) {
            return new String(fis.readAllBytes());
        }
    }

    // 生成静态页面（调用链隐藏漏洞）
    public void generateStaticPage(String categoryPinyin, String templateName, String content) throws IOException {
        Path targetPath = buildFilePath(categoryPinyin, templateName);
        
        // 创建目录结构
        Files.createDirectories(targetPath.getParent());
        
        // 写入文件内容
        Files.write(targetPath, content.getBytes());
    }

    // 获取分类模板列表
    public List<String> listTemplates(String categoryPinyin) throws IOException {
        Path dirPath = buildFilePath(categoryPinyin, "");
        
        if (!Files.exists(dirPath)) {
            return List.of();
        }
        
        return Files.list(dirPath).map(Path::getFileName).map(Path::toString).collect(Collectors.toList());
    }
}