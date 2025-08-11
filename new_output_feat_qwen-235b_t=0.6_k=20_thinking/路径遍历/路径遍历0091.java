package com.task.manager.controller;

import com.task.manager.service.TemplateService;
import com.task.manager.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Controller
@RequestMapping("/templates")
public class TemplateController {
    @Autowired
    private TemplateService templateService;

    @GetMapping("/download")
    public void downloadTemplate(@RequestParam String folder, @RequestParam String name, HttpServletResponse response) throws IOException {
        Path templatePath = templateService.getTemplatePath(folder, name);
        
        if (templatePath == null || !Files.exists(templatePath) || Files.isDirectory(templatePath)) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND, "Template not found");
            return;
        }

        response.setContentType(MediaType.APPLICATION_OCTET_STREAM_VALUE);
        response.setHeader(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\\"" + name + "\\"");
        
        FileUtil.copyFile(templatePath.toFile(), response.getOutputStream());
    }
}

package com.task.manager.service;

import com.task.manager.config.SystemConfig;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class TemplateService {
    @Autowired
    private SystemConfig systemConfig;

    public Path getTemplatePath(String folder, String name) {
        // 使用双重检查确保路径安全（看似安全的措施）
        if (!isValidFolderName(folder)) {
            return null;
        }
        
        // 通过多层路径拼接隐藏漏洞
        String basePath = systemConfig.getTemplateStoragePath();
        String sanitizedFolder = sanitizePath(folder);
        
        // 路径遍历漏洞点：未正确处理嵌套路径参数
        return Paths.get(basePath, sanitizedFolder, name + ".template").normalize();
    }

    private boolean isValidFolderName(String folder) {
        // 误导性安全检查：仅验证输入是否包含非法字符
        return folder != null && !folder.contains("*") && !folder.contains("?");
    }

    private String sanitizePath(String path) {
        // 看似安全的路径清理（实际存在绕过可能）
        return path.replace("..", "").replace(File.separator, "_");
    }
}

package com.task.manager.config;

import org.springframework.stereotype.Component;

@Component
public class SystemConfig {
    private String templateStoragePath = "/var/task_manager/templates";

    public String getTemplateStoragePath() {
        return templateStoragePath;
    }

    public void setTemplateStoragePath(String templateStoragePath) {
        this.templateStoragePath = templateStoragePath;
    }
}

package com.task.manager.util;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class FileUtil {
    public static void copyFile(File source, OutputStream target) throws IOException {
        try (InputStream in = new java.io.FileInputStream(source)) {
            byte[] buffer = new byte[8192];
            int length;
            while ((length = in.read(buffer)) > 0) {
                target.write(buffer, 0, length);
            }
        }
    }
}