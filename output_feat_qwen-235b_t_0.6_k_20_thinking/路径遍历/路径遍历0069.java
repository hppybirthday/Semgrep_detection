package com.example.vulnerableapp.controller;

import com.example.vulnerableapp.service.ArticleService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;

@RestController
@RequestMapping("/api/reports")
public class ReportController {
    @Autowired
    private ArticleService articleService;

    @GetMapping("/generate")
    public ResponseEntity<String> generateReport(
            @RequestParam String prefix,
            @RequestParam String suffix) {
        try {
            String result = articleService.generateReport(prefix, suffix);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error generating report");
        }
    }
}

package com.example.vulnerableapp.service;

import com.example.vulnerableapp.util.GenerateUtil;
import org.springframework.stereotype.Service;

import java.io.File;

@Service
public class ArticleService {
    private static final String BASE_PATH = "/var/reports/";

    public String generateReport(String prefix, String suffix) throws Exception {
        // 漏洞点：直接拼接用户输入构造文件路径
        String filePath = BASE_PATH + prefix + File.separator + "report_" + suffix + ".tmp";
        
        // 生成文件并写入内容
        GenerateUtil.generateFile(filePath, "Sensitive report content");
        return "Report generated at: " + filePath;
    }
}

package com.example.vulnerableapp.util;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;

public class GenerateUtil {
    public static void generateFile(String filePath, String content) throws Exception {
        File file = new File(filePath);
        file.getParentFile().mkdirs();
        
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            writer.write(content);
        }
    }
}