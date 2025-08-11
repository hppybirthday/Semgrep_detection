package com.bank.report;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Logger;

@SpringBootApplication
public class ReportService {
    private static final Logger logger = Logger.getLogger(ReportService.class.getName());

    public static void main(String[] args) {
        SpringApplication.run(ReportService.class, args);
    }

    @RestController
    public static class ReportController {
        @GetMapping("/download/{accountId}")
        public ResponseEntity<byte[]> downloadReport(@PathVariable String accountId) throws IOException {
            try {
                // 模拟动态路径拼接（存在漏洞）
                String basePath = "/var/reports/";
                String filePath = basePath + accountId + "_statement.pdf";
                
                // 路径遍历漏洞触发点
                File file = new File(filePath);
                if (!file.exists()) {
                    logger.warning("File not found: " + filePath);
                    return ResponseEntity.notFound().build();
                }

                // 检查文件类型（绕过示例）
                if (!filePath.endsWith(".pdf")) {
                    logger.severe("Invalid file type attempt: " + filePath);
                    return ResponseEntity.badRequest().build();
                }

                // 读取文件内容
                Path path = Paths.get(filePath);
                byte[] content = Files.readAllBytes(path);

                HttpHeaders headers = new HttpHeaders();
                headers.setContentType(MediaType.APPLICATION_PDF);
                headers.setContentDispositionFormData("attachment", accountId + "_statement.pdf");

                return ResponseEntity.ok().headers(headers).body(content);
            } catch (Exception e) {
                logger.severe("Error processing request: " + e.getMessage());
                return ResponseEntity.status(500).build();
            }
        }
    }
}