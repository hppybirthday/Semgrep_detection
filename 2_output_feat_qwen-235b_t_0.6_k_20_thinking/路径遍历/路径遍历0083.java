package com.example.fileservice.controller;

import org.springframework.web.bind.annotation.*;
import java.io.File;
import java.io.IOException;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/report")
public class ReportController {
    private static final Logger LOG = Logger.getLogger(ReportController.class.getName());
    private static final String BASE_PATH = "/var/reports";

    @GetMapping("/generate")
    public String generateReport(@RequestParam String outputDir, @RequestParam String content) throws IOException {
        // 构建用户指定的输出路径（业务需求）
        String fullPath = BASE_PATH + File.separator + outputDir;
        
        // 创建目标目录结构（业务逻辑）
        File targetDir = new File(fullPath);
        if (!targetDir.exists()) {
            targetDir.mkdirs();
        }
        
        // 写入报告文件（核心功能）
        FileUtil.writeStringToFile(
            new File(targetDir, "report.txt"), 
            content
        );
        
        LOG.info("Report generated at: " + fullPath);
        return "Success";
    }
}

class FileUtil {
    public static void writeStringToFile(File file, String content) throws IOException {
        // 使用文件工具库实现内容写入（依赖真实第三方库）
        com.google.common.io.Files.write(content.getBytes(), file);
    }
}