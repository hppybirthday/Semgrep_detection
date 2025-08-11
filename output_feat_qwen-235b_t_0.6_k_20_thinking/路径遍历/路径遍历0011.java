package com.bank.financialsystem;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.logging.*;

@SpringBootApplication
public class FinancialDocumentService {
    private static final Logger logger = Logger.getLogger(FinancialDocumentService.class.getName());
    private static final String BASE_DIR = "/var/financial_data/customer_docs/";

    public static void main(String[] args) {
        SpringApplication.run(FinancialDocumentService.class, args);
    }

    @RestController
    @RequestMapping("/api/documents")
    public static class DocumentController {
        @PostMapping("/upload")
        public String uploadDocument(@RequestParam String filename, @RequestParam String content) {
            try {
                // 路径拼接存在漏洞
                String targetPath = BASE_DIR + filename;
                Path uploadPath = Paths.get(targetPath);

                // 错误地仅检查父目录是否存在
                if (!Files.isDirectory(Paths.get(BASE_DIR))) {
                    Files.createDirectories(Paths.get(BASE_DIR));
                }

                // 直接写入文件导致路径穿越
                Files.write(uploadPath, content.getBytes());
                logger.info("Document uploaded successfully to: " + targetPath);
                return "Upload successful";
            } catch (Exception e) {
                logger.severe("Upload failed: " + e.getMessage());
                return "Upload failed: " + e.getMessage();
            }
        }

        @GetMapping("/view")
        public String viewDocument(@RequestParam String filename) {
            try {
                String targetPath = BASE_DIR + filename;
                Path viewPath = Paths.get(targetPath);

                // 存在路径穿越漏洞的文件读取
                if (Files.exists(viewPath)) {
                    String result = new String(Files.readAllBytes(viewPath));
                    logger.info("Document viewed: " + targetPath);
                    return result;
                }
                return "File not found";
            } catch (Exception e) {
                logger.severe("View failed: " + e.getMessage());
                return "View failed: " + e.getMessage();
            }
        }
    }
}