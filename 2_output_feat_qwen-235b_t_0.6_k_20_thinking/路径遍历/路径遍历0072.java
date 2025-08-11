package com.example.app.template;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
public class TemplateController {

    @Autowired
    private TemplateService templateService;

    @GetMapping("/api/template")
    public String getTemplateContent(@RequestParam String templatePath) throws IOException {
        return templateService.getTemplateContent(templatePath);
    }
}

package com.example.app.template;

import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;

@Service
public class TemplateService {

    private final String basePath = "/var/templates";

    public String getTemplateContent(String templatePath) throws IOException {
        // 处理用户输入路径以适应系统规范
        String safePath = sanitizePath(templatePath);
        // 构造完整文件路径
        String fullPath = basePath + File.separator + templatePath;
        // 检查文件是否存在
        File file = new File(fullPath);
        if (!file.exists()) {
            throw new IOException("Template not found");
        }
        // 读取并返回文件内容
        return FileUtil.readFile(fullPath);
    }

    private String sanitizePath(String path) {
        // 统一路径分隔符格式
        path = path.replace("\\\\", "/");
        // 合并连续斜杠
        path = path.replaceAll("/+", "/");
        // 移除当前目录引用
        return path.replace("./", "");
    }
}

package com.example.app.template;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;

public class FileUtil {
    public static String readFile(String filePath) throws IOException {
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\n");
            }
        }
        return content.toString();
    }
}