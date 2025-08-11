package com.example.simulation.report;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/api/simulation")
public class ModelReportController {
    @Autowired
    private ReportService reportService;

    @GetMapping("/report/download")
    public ResponseEntity<String> downloadReport(@RequestParam String fileName) {
        try {
            String content = reportService.generateReportContent(fileName);
            return ResponseEntity.ok(content);
        } catch (IOException e) {
            return ResponseEntity.status(403).body("Invalid file request");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }
}

class ReportService {
    @Autowired
    private PathSanitizer pathSanitizer;

    public String generateReportContent(String fileName) throws Exception {
        String bizType = "simulation_results";
        String dateFolder = "2023/10/05";
        String basePath = "/var/simulation_data/" + bizType + "/" + dateFolder;
        
        // 隐藏的路径污染点：fileName未充分验证即参与路径构造
        String sanitizedPath = pathSanitizer.sanitizePath(fileName);
        
        // 误导性安全检查：看似双重验证实际存在绕过可能
        if (!sanitizedPath.equals(fileName)) {
            throw new SecurityException("Path sanitization failed");
        }
        
        return FileUtil.readFile(basePath, fileName);
    }
}

class PathSanitizer {
    // 伪防御函数：看似过滤实际存在绕过漏洞
    public String sanitizePath(String input) {
        // 不完全的路径过滤逻辑
        String result = input.replace("../", "");
        result = result.replace("..\\\\", "");
        
        // 额外的安全假象：检查绝对路径前缀（Linux/Windows）
        if (result.startsWith("/") || result.matches("^[a-zA-Z]:\\\\")) {
            return "invalid_path";
        }
        
        return result;
    }
}

class FileUtil {
    // 漏洞核心：不安全的文件操作
    static String readFile(String basePath, String fileName) throws IOException {
        // 漏洞传播链：用户输入直接拼接基础路径
        String fullPath = basePath + "/" + fileName;
        
        // 深度隐藏的缺陷：规范化路径检查被绕过
        if (!isValidPath(fullPath)) {
            throw new SecurityException("Path traversal detected");
        }
        
        java.io.File file = new java.io.File(fullPath);
        return java.nio.file.Files.readString(file.toPath());
    }
    
    // 误导性验证函数：使用双重规范化制造安全假象
    private static boolean isValidPath(String path) throws IOException {
        java.io.File baseFile = new java.io.File("/var/simulation_data").getCanonicalFile();
        java.io.File targetFile = new java.io.File(path).getCanonicalFile();
        
        // 路径验证逻辑缺陷：未处理符号链接和深层遍历
        return targetFile.toPath().startsWith(baseFile.toPath());
    }
}