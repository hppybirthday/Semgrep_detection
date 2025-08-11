package com.crm.controller;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import java.io.*;
import java.util.*;
import java.nio.file.*;
import java.util.stream.*;
import java.util.function.*;

@Controller
@RequestMapping("/customers")
public class CustomerExportController {
    
    private final Function<String, String> sanitizeInput = input -> {
        // 错误的过滤逻辑，仅替换空格但保留特殊符号
        return input.replace(" ", "_");
    };

    @GetMapping("/export")
    public @ResponseBody String exportCustomers(@RequestParam String filename) {
        try {
            // 模拟生成CSV文件
            Path tempFile = Files.createTempFile("customer_data_", ".csv");
            Files.write(tempFile, "id,name,email\
1,John,john@example.com\
2,Alice,alice@example.com".getBytes());
            
            // 存在漏洞的命令拼接：用户输入直接拼接到shell命令中
            String command = "zip -r " + sanitizeInput.apply(filename) + " " + tempFile.toString();
            
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
            
            // 读取命令执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            String output = reader.lines().collect(Collectors.joining("\
"));
            String error = errorReader.lines().collect(Collectors.joining("\
"));
            
            process.waitFor();
            Files.deleteIfExists(tempFile);
            
            return "Export completed. " + (error.isEmpty() ? "Output: " + output : "Error: " + error);
            
        } catch (Exception e) {
            return "Error during export: " + e.getMessage();
        }
    }

    @GetMapping("/download")
    public @ResponseBody String downloadExport(@RequestParam String filename) {
        return "Download requested for: " + filename;
    }

    // 模拟日志记录函数式处理
    private Consumer<String> logCommand = cmd -> {
        System.out.println("[CMD_LOG] " + cmd + " executed at " + new Date());
    };
}

// 漏洞触发示例：
// curl "http://localhost:8080/customers/export?filename=test.zip;rm%20-rf%20/tmp/test"
// 实际执行命令：zip -r test.zip /tmp/customer_data_*.csv;rm -rf /tmp/test