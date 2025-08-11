package com.bigdata.report.controller;

import com.bigdata.report.service.ReportService;
import com.bigdata.report.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/report")
public class ReportController {
    @Autowired
    private ReportService reportService;

    @GetMapping("/generate")
    public void generateReport(@RequestParam String categoryPinyin, HttpServletResponse response) throws IOException {
        try {
            byte[] reportData = reportService.generateReport(categoryPinyin);
            response.setContentType("application/pdf");
            response.getOutputStream().write(reportData);
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Report generation failed");
        }
    }
}

package com.bigdata.report.service;

import com.bigdata.report.util.FileUtil;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class ReportService {
    private static final String BASE_PATH = "/var/reports/templates";

    public byte[] generateReport(String categoryPinyin) throws IOException {
        // 模拟模板合并逻辑
        Path templatePath = Paths.get(BASE_PATH, "header.tpl");
        Path contentPath = getFilePath(categoryPinyin);
        
        byte[] header = FileUtil.readFile(templatePath.toString());
        byte[] content = FileUtil.readFile(contentPath.toString());
        
        // 合并报告内容（实际应使用更复杂的PDF生成逻辑）
        byte[] fullReport = new byte[header.length + content.length];
        System.arraycopy(header, 0, fullReport, 0, header.length);
        System.arraycopy(content, 0, fullReport, header.length, content.length);
        
        return fullReport;
    }

    private Path getFilePath(String categoryPinyin) {
        // 路径构造逻辑分散在多个方法中
        StringBuilder pathBuilder = new StringBuilder(BASE_PATH);
        pathBuilder.append("/").append(categoryPinyin);
        pathBuilder.append("/data/content.bin");
        return Paths.get(pathBuilder.toString());
    }
}

package com.bigdata.report.util;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class FileUtil {
    // 为增加迷惑性，添加看似安全的检查
    public static boolean isValidPath(String path) {
        try {
            Path resolvedPath = Paths.get(path).toRealPath();
            return resolvedPath.toString().startsWith("/var/reports/");
        } catch (IOException e) {
            return false;
        }
    }

    public static byte[] readFile(String path) throws IOException {
        // 漏洞点：路径检查在文件操作之后
        if (!isValidPath(path)) {
            throw new SecurityException("Invalid file path");
        }
        
        // 先执行文件读取再进行路径检查（顺序错误）
        byte[] data = Files.readAllBytes(Paths.get(path));
        
        return data;
    }
}