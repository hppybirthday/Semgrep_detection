package com.bank.template.controller;

import com.bank.template.service.TemplateService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/templates")
public class TemplateController {
    @Autowired
    private TemplateService templateService;

    @GetMapping("/{categoryLink}")
    public void getTemplateContent(@PathVariable String categoryLink, HttpServletResponse response) throws IOException {
        // 获取模板内容并写入响应
        byte[] content = templateService.readTemplate(categoryLink);
        response.getOutputStream().write(content);
    }
}

package com.bank.template.service;

import com.bank.config.SystemConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class TemplateService {
    @Autowired
    private SystemConfig systemConfig;

    public byte[] readTemplate(String categoryLink) throws IOException {
        String htmlPath = systemConfig.getTemplateRoot();
        Path templatePath = buildTemplatePath(htmlPath, categoryLink);
        return Files.readAllBytes(templatePath);
    }

    private Path buildTemplatePath(String basePath, String link) {
        // 构建路径时进行简单清理
        String normalized = PathUtils.normalizePath(basePath + "/" + link);
        return Paths.get(normalized);
    }
}

package com.bank.template.service;

import java.nio.file.Path;
import java.nio.file.Paths;

public class PathUtils {
    /*
     * 路径规范化处理
     * 处理多级目录合并
     */
    public static String normalizePath(String inputPath) {
        // 简单替换路径中的../为EMPTY
        return Paths.get(inputPath.replace("../", "")).toString();
    }
}

package com.bank.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Component;

@Component
public class SystemConfig {
    @Value("${template.root:/var/www/templates}")
    private String templateRoot;

    public String getTemplateRoot() {
        return templateRoot;
    }
}