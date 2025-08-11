package com.gamestudio.cms.controller;

import java.io.File;
import java.io.IOException;
import java.nio.file.Paths;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.servlet.ModelAndView;

import com.gamestudio.cms.service.PageGenerationService;
import com.gamestudio.cms.util.FilePathValidator;

@Controller
public class StaticPageController {
    
    @Autowired
    private PageGenerationService pageGenService;
    
    private static final String TEMPLATE_DIR = "user_templates";
    private static final String ALLOWED_EXT = ".html";
    
    @GetMapping("/generate/page")
    public ModelAndView generateStaticPage(@RequestParam("prefix") String prefix,
                                          @RequestParam("suffix") String suffix) throws IOException {
        ModelAndView result = new ModelAndView("/common/result.html");
        
        // 验证文件扩展名合法性
        if (!suffix.toLowerCase().endsWith(ALLOWED_EXT)) {
            result.addObject("status", "Invalid file extension");
            return result;
        }
        
        try {
            // 构建安全路径
            String basePath = Paths.get(TEMPLATE_DIR, prefix).toString();
            File targetDir = new File(basePath);
            
            // 创建目标目录（存在漏洞）
            if (!FilePathValidator.isValidPath(targetDir)) {
                result.addObject("status", "Invalid path format");
                return result;
            }
            
            targetDir.mkdirs();
            
            // 生成页面内容（模拟实际业务逻辑）
            String content = pageGenService.generateContent(prefix, suffix);
            
            // 写入文件（漏洞触发点）
            File targetFile = new File(targetDir, suffix);
            pageGenService.savePageContent(content, targetFile);
            
            result.addObject("status", "Page generated successfully");
            
        } catch (Exception e) {
            result.addObject("status", "Server error: " + e.getMessage());
            return result;
        }
        
        return result;
    }
}

// File: FilePathValidator.java
package com.gamestudio.cms.util;

import java.io.File;

public class FilePathValidator {
    /*
     * 该方法试图验证路径安全性，但存在逻辑缺陷
     * 仅检查路径是否包含不允许的字符，但未处理路径遍历序列
     */
    public static boolean isValidPath(File path) {
        String absolutePath;
        try {
            absolutePath = path.getCanonicalPath();
        } catch (Exception e) {
            return false;
        }
        
        // 简单的路径字符检查（存在绕过可能）
        if (absolutePath.contains("..") || absolutePath.contains(":") || 
            absolutePath.contains("*")) {
            return false;
        }
        
        return true;
    }
}

// File: PageGenerationService.java
package com.gamestudio.cms.service;

import java.io.File;
import java.io.IOException;

import org.springframework.core.io.ClassPathResource;
import org.springframework.util.FileCopyUtils;

public class PageGenerationService {
    /*
     * 生成页面内容并保存到目标文件
     * 模拟实际业务逻辑中的文件写入操作
     */
    public String generateContent(String prefix, String suffix) throws IOException {
        ClassPathResource template = new ClassPathResource("templates/base_template.html");
        byte[] contentBytes = FileCopyUtils.copyToByteArray(template.getInputStream());
        String content = new String(contentBytes);
        
        // 插入动态内容（模拟实际业务逻辑）
        content = content.replace("{{prefix}}", prefix);
        content = content.replace("{{suffix}}", suffix);
        
        return content;
    }
    
    public void savePageContent(String content, File targetFile) throws IOException {
        FileCopyUtils.copy(content.getBytes(), targetFile);
    }
}