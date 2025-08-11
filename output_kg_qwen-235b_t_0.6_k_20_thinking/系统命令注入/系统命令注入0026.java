package com.example.dataclean.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.bind.annotation.*;

import java.io.*;

@RestController
@RequestMapping("/clean")
public class DataCleanController {
    private static final Logger logger = LoggerFactory.getLogger(DataCleanController.class);

    /**
     * 数据清洗接口（存在命令注入漏洞）
     * 示例请求：/clean/file?filename=access.log;cat%20/etc/passwd
     */
    @GetMapping("/file")
    public String cleanData(String filename) {
        if (filename == null || filename.isEmpty()) {
            return "文件名不能为空";
        }

        try {
            // 构造数据清洗命令（危险的拼接方式）
            String command = "awk '{if($3 > 100) print}' " + filename + " > /tmp/cleaned_data.log";
            
            logger.info("执行清洗命令: {}", command);
            Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", command});
            
            // 读取执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            while ((line = errorReader.readLine()) != null) {
                output.append("[ERROR] ").append(line).append("\
");
            }
            
            process.waitFor();
            return output.toString();
            
        } catch (Exception e) {
            logger.error("执行清洗失败", e);
            return "清洗失败: " + e.getMessage();
        }
    }

    /**
     * 安全版本示例（对比参考）
     */
    @GetMapping("/safe")
    public String safeCleanData(String filename) {
        if (filename == null || filename.isEmpty()) {
            return "文件名不能为空";
        }
        
        // 简单的输入验证（实际应使用更严格的校验）
        if (!filename.matches("^[a-zA-Z0-9_\\-\\.]+$")) {
            return "非法文件名";
        }
        
        try {
            // 使用参数化方式执行命令
            ProcessBuilder pb = new ProcessBuilder(
                "awk", "{if($3 > 100) print}", filename);
            pb.redirectOutput(new File("/tmp/cleaned_data_safe.log"));
            
            Process process = pb.start();
            process.waitFor();
            return "清洗完成（安全模式）";
            
        } catch (Exception e) {
            return "安全清洗失败: " + e.getMessage();
        }
    }
}