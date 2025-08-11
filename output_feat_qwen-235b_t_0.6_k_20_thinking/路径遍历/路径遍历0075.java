package com.bank.report;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@SpringBootApplication
public class ReportApplication {
    private static final String BASE_DIR = "/var/reports/bank/";
    private static final Map<String, String> TEMPLATE_MAP = new ConcurrentHashMap<>();

    static {
        TEMPLATE_MAP.put("monthly", "MonthlyStatement.tpl");
        TEMPLATE_MAP.put("annual", "AnnualSummary.tpl");
    }

    public static void main(String[] args) {
        SpringApplication.run(ReportApplication.class, args);
    }

    @RestController
    public static class ReportController {
        @GetMapping("/export")
        public String exportReport(@RequestParam String reportType,
                                  @RequestParam String outputDir) throws IOException {
            
            // 漏洞点：直接拼接用户输入的路径参数
            String templateName = TEMPLATE_MAP.getOrDefault(reportType, "default.tpl");
            String filePath = BASE_DIR + outputDir + File.separator + templateName;
            
            Path path = Paths.get(filePath);
            
            // 危险操作：直接检查用户指定路径的文件是否存在
            if (!Files.exists(path.getParent())) {
                Files.createDirectories(path.getParent());
            }

            // 模拟文件写入操作
            if (Files.exists(path)) {
                return String.format("Report exported to: %s (size: %dKB)", 
                    path.toAbsolutePath(), Files.size(path)/1024);
            } else {
                Files.createFile(path);
                return String.format("New report created at: %s", path.toAbsolutePath());
            }
        }

        // 元编程风格的动态配置方法
        @PostMapping("/config")
        public String updateTemplate(@RequestParam String key, 
                                   @RequestParam String templateName) {
            TEMPLATE_MAP.put(key, templateName);
            return String.format("Template updated: %s -> %s", key, templateName);
        }
    }
}