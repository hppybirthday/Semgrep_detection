package com.example.bank.controller;

import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.net.MalformedURLException;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/v1/reports")
public class FinancialReportController {
    
    // 模拟银行报告存储路径
    private static final String REPORTS_DIR = "bank_data/reports";
    
    /**
     * 路径遍历漏洞示例：通过构造恶意filename参数访问任意文件
     * 示例攻击请求：/api/v1/reports/download?filename=../../../../etc/passwd
     */
    @GetMapping("/download")
    public ResponseEntity<Resource> downloadReport(@RequestParam String filename) {
        try {
            // 漏洞点：直接拼接用户输入
            Path filePath = Paths.get(REPORTS_DIR).resolve(filename).normalize();
            
            // 未正确验证路径是否超出限定目录
            if (!filePath.startsWith(REPORTS_DIR)) {
                throw new SecurityException("路径越权访问");
            }
            
            Resource resource = new UrlResource(filePath.toUri());
            
            if (resource.exists() || resource.isReadable()) {
                return ResponseEntity.ok()
                    .contentType(MediaType.APPLICATION_OCTET_STREAM)
                    .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\\"" + resource.getFilename() + "\\"")
                    .body(resource);
            } else {
                throw new RuntimeException("无法读取文件");
            }
        } catch (MalformedURLException e) {
            throw new RuntimeException("文件下载异常", e);
        }
    }
    
    /**
     * 安全版本示例（已注释）
    @GetMapping("/download_safe")
    public ResponseEntity<Resource> downloadReportSafe(@RequestParam String filename) {
        try {
            // 强制限定在报告目录
            Path targetDir = Paths.get(REPORTS_DIR).toRealPath();
            Path filePath = targetDir.resolve(filename);
            
            // 二次验证路径合法性
            if (!filePath.toRealPath().startsWith(targetDir.toString())) {
                throw new SecurityException("路径越权访问");
            }
            
            Resource resource = new UrlResource(filePath.toUri());
            return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\\"" + resource.getFilename() + "\\"")
                .body(resource);
        } catch (Exception e) {
            throw new RuntimeException("文件下载异常", e);
        }
    }
    */
    
    // 模拟其他银行接口
    @GetMapping("/transactions")
    public String getTransactions() {
        return "交易记录数据...";
    }
    
    @PostMapping("/upload")
    public String uploadReport(@RequestParam String content) {
        // 模拟报告生成逻辑
        return "报告上传成功";
    }
    
    // 模拟系统日志接口
    @GetMapping("/logs")
    public String getLogs() {
        return "[ERROR] 认证失败\
[INFO] 系统启动成功\
[DEBUG] 内存占用：120MB";
    }
    
    // 模拟账户信息接口
    @GetMapping("/account/{id}")
    public String getAccountInfo(@PathVariable String id) {
        return "{\\"balance\\": 1500000.00, \\"currency\\": \\"USD\\"}";
    }
}