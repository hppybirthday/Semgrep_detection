package com.example.productcatalog;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;

@RestController
@RequestMapping("/api/categories")
public class CategoryController {
    private final CategoryService categoryService = new CategoryService();

    @PostMapping
    public String createCategory(@RequestBody CategoryRequest request) {
        try {
            return categoryService.createCategory(request.getPrefix(), request.getSuffix(), request.getContent());
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class CategoryRequest {
    private String prefix;
    private String suffix;
    private String content;
    
    // Getters and setters
    public String getPrefix() { return prefix; }
    public void setPrefix(String prefix) { this.prefix = prefix; }
    public String getSuffix() { return suffix; }
    public void setSuffix(String suffix) { this.suffix = suffix; }
    public String getContent() { return content; }
    public void setContent(String content) { this.content = content; }
}

class CategoryService {
    private static final String BASE_DIR = "/var/www/uploads/";
    
    public String createCategory(String prefix, String suffix, String content) throws IOException {
        // 漏洞点：直接拼接用户输入构造路径
        String targetPath = BASE_DIR + prefix + "/config/" + suffix + ".txt";
        File targetFile = new File(targetPath);
        
        // 创建父目录（可能创建任意目录结构）
        if (!targetFile.getParentFile().exists()) {
            targetFile.getParentFile().mkdirs();
        }
        
        // 写入文件内容（可能覆盖任意文件）
        try (FileOutputStream fos = new FileOutputStream(targetFile)) {
            fos.write(content.getBytes());
        }
        
        return "Category created at: " + targetPath;
    }
}