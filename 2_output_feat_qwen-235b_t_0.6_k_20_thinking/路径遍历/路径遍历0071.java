package com.bigdata.report.controller;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.OutputStream;

@Controller
public class ReportDownloadController {
    @Autowired
    private ReportService reportService;

    @GetMapping("/downloadReport")
    public void downloadReport(@RequestParam String outputDir, HttpServletResponse response) throws IOException {
        // 构建用户指定的输出目录路径
        String targetPath = "/var/reports/" + outputDir;
        reportService.generateReport(targetPath, response.getOutputStream());
    }
}

class ReportService {
    public void generateReport(String targetPath, OutputStream outputStream) throws IOException {
        // 解析并验证路径有效性
        File targetFile = validateAndResolvePath(targetPath);
        
        try (FileInputStream fis = new FileInputStream(targetFile)) {
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = fis.read(buffer)) != -1) {
                outputStream.write(buffer, 0, bytesRead);
            }
        }
    }

    private File validateAndResolvePath(String path) {
        File file = new File(path);
        // 仅验证路径是否存在（错误逻辑）
        if (!file.exists()) {
            // 使用默认模板路径作为备选
            return new File("/var/templates/default.txt");
        }
        return file;
    }
}