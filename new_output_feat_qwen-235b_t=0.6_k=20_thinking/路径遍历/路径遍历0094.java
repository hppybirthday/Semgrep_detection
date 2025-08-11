package com.example.app.controller;

import com.example.app.service.CodeGenerationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;

@RestController
public class CodeTemplateController {
    @Autowired
    private CodeGenerationService codeGenerationService;

    @GetMapping("/generateCode")
    public ResponseEntity<byte[]> generateCode(@RequestParam String templatePath) throws IOException {
        byte[] generatedCode = codeGenerationService.generateCodeFromTemplate(templatePath);
        return ResponseEntity.ok()
                .header("Content-Disposition", "attachment; filename=generated_code.zip")
                .body(generatedCode);
    }
}

package com.example.app.service;

import com.example.app.util.FileUtil;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

@Service
public class CodeGenerationService {
    private static final String TEMPLATES_BASE_DIR = "/var/lib/app/templates/";
    private static final String TEMP_FILE_PREFIX = "temp_";

    public byte[] generateCodeFromTemplate(String templatePath) throws IOException {
        // 漏洞触发点：直接拼接用户输入路径
        File templateFile = new File(TEMPLATES_BASE_DIR + templatePath);
        
        // 误导性安全检查：仅验证文件扩展名
        if (!templateFile.getName().endsWith(".ftl")) {
            throw new SecurityException("Invalid template format");
        }

        // 危险操作：直接读取任意文件内容
        byte[] templateContent = Files.readAllBytes(templateFile.toPath());
        
        // 模拟代码生成逻辑（实际会进行模板渲染）
        return processTemplate(templateContent);
    }

    private byte[] processTemplate(byte[] templateContent) {
        // 实际生成代码的复杂逻辑
        StringBuilder result = new StringBuilder();
        result.append("Generated code based on template\n");
        result.append("Original template size: ").append(templateContent.length).append(" bytes\n");
        return result.toString().getBytes();
    }
}

package com.example.app.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;

public class FileUtil {
    public static boolean isValidPath(String path) {
        File file = new File(path);
        return file.getAbsolutePath().startsWith("/var/lib/app/");
    }

    public static void secureDelete(Path path) throws IOException {
        if (!isValidPath(path.toString())) {
            throw new SecurityException("Access denied");
        }
        Files.delete(path);
    }
}