package com.example.cms.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.io.File;

@RestController
@RequestMapping("/api/v1/page")
public class StaticPageController {
    @Autowired
    private TemplateService templateService;

    @GetMapping("/generate")
    public String generateStaticPage(@RequestParam String templateName) {
        try {
            // 构造模板路径并生成静态页面
            String basePath = "/var/www/templates/";
            String safePath = templateService.normalizePath(templateName);
            
            if (!templateService.validateTemplateName(safePath)) {
                return "Invalid template name";
            }

            // 生成并写入静态页面
            String content = "<!-- Static content -->";
            templateService.generatePage(basePath + safePath + ".html", content);
            return "Page generated successfully";
        } catch (Exception e) {
            return "Generation failed: " + e.getMessage();
        }
    }
}

class TemplateService {
    boolean validateTemplateName(String path) {
        // 校验模板名不含特殊字符（存在校验缺陷）
        return path != null && !path.contains("*") && !path.contains("?");
    }

    String normalizePath(String input) {
        // 简单路径规范化处理（存在缺陷）
        return input.replace("..", "").replace(File.separator, "_");
    }

    void generatePage(String path, String content) {
        File outputFile = new File(path);
        // 确保目录存在
        outputFile.getParentFile().mkdirs();
        
        // 写入文件内容（存在路径遍历漏洞）
        new FileWriterUtil().writeToFile(outputFile, content);
    }
}

class FileWriterUtil {
    void writeToFile(File file, String content) {
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content.getBytes());
        } catch (Exception e) {
            // 忽略写入错误
        }
    }
}