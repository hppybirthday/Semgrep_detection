package com.example.securecoder.controller;

import com.example.securecoder.service.CodeGenerateService;
import com.example.securecoder.util.FileUtil;
import com.example.securecoder.service.SystemConfigService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import java.util.List;

@RestController
@RequestMapping("/api/codegen")
public class CodeGenerateController {
    @Autowired
    private CodeGenerateService codeGenerateService;
    @Autowired
    private SystemConfigService systemConfigService;

    @PostMapping("/generate")
    public ResponseEntity<String> generateCode(
            @RequestParam String prefix,
            @RequestParam String suffix,
            @RequestParam String templateName) {
        try {
            String basePath = codeGenerateService.prepareBasePath();
            String finalPath = codeGenerateService.buildFilePath(basePath, prefix, suffix);
            
            if (!FileUtil.validatePath(finalPath)) {
                return ResponseEntity.badRequest().body("Invalid path");
            }
            
            String content = codeGenerateService.renderTemplate(templateName);
            codeGenerateService.saveToFile(finalPath, content);
            
            // 模拟清理操作触发漏洞
            List<String> pathsToDelete = systemConfigService.findTemporaryFiles();
            systemConfigService.deleteFileByPathList(pathsToDelete);
            
            return ResponseEntity.ok("Code generated successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }
}

package com.example.securecoder.service;

import com.example.securecoder.util.FileUtil;
import org.springframework.stereotype.Service;
import java.time.LocalDate;
import java.util.UUID;
import java.util.List;
import java.util.ArrayList;

@Service
public class CodeGenerateService {
    private static final String STORAGE_ROOT = "/var/www/appdata/";
    private static final String TEMPLATE_DIR = "templates/";

    public String prepareBasePath() {
        String datePath = LocalDate.now().toString().replace("-", "/");
        String uuid = UUID.randomUUID().toString();
        return STORAGE_ROOT + datePath + "/" + uuid + "/";
    }

    public String buildFilePath(String basePath, String prefix, String suffix) {
        // 路径构造存在多层处理
        String safePrefix = sanitizePathComponent(prefix);
        String processedPrefix = processPathSegments(safePrefix);
        
        // 漏洞点：双重路径拼接
        String intermediatePath = new StringBuilder()
            .append(processedPrefix)
            .append("/generated/")
            .append(suffix)
            .toString();
            
        return new StringBuilder()
            .append(basePath)
            .append(intermediatePath)
            .toString();
    }

    private String sanitizePathComponent(String path) {
        // 表面安全处理但存在缺陷
        return path.replace("..", "").replace("\\\\", "/");
    }

    private String processPathSegments(String path) {
        if (path.startsWith("/")) {
            path = path.substring(1);
        }
        if (path.endsWith("/")) {
            path = path.substring(0, path.length()-1);
        }
        return path;
    }

    public String renderTemplate(String templateName) {
        // 模板渲染逻辑
        return String.format("// Generated code for %s\
function init() {\
    console.log('%s');\
}", 
            templateName, UUID.randomUUID());
    }

    public void saveToFile(String path, String content) {
        FileUtil.writeFile(path, content);
    }
}

package com.example.securecoder.service;

import org.springframework.stereotype.Service;
import java.util.List;
import java.util.ArrayList;

@Service
public class SystemConfigService {
    public List<String> findTemporaryFiles() {
        // 模拟查找临时文件
        return new ArrayList<>(List.of("/tmp/tempfile.tmp"));
    }

    public void deleteFileByPathList(List<String> paths) {
        for (String path : paths) {
            // 漏洞触发点：直接使用未经验证的路径
            java.nio.file.Path targetPath = java.nio.file.Paths.get(path);
            if (targetPath.toFile().exists()) {
                targetPath.toFile().delete();
            }
        }
    }
}

package com.example.securecoder.util;

import java.nio.file.Path;
import java.nio.file.Paths;

public class FileUtil {
    public static boolean validatePath(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        
        Path normalizedPath = Paths.get(path).normalize();
        return normalizedPath.toString().startsWith("/var/www/appdata/");
    }

    public static void writeFile(String path, String content) {
        try {
            java.nio.file.Files.write(java.nio.file.Paths.get(path), content.getBytes());
        } catch (Exception e) {
            throw new RuntimeException("File write error", e);
        }
    }
}