package com.crm.example;

import java.io.*;
import java.util.concurrent.TimeUnit;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class CustomerExportController {
    
    @GetMapping("/export")
    public String exportData(@RequestParam String filePath) {
        Process process;
        try {
            // 构造危险命令：直接拼接用户输入
            String cmd = "export_data.sh " + filePath;
            
            // 使用ProcessBuilder执行命令
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", cmd);
            pb.redirectErrorStream(true);
            process = pb.start();
            
            // 等待命令执行完成
            if (!process.waitFor(10, TimeUnit.SECONDS)) {
                process.destroy();
                return "Timeout";
            }
            
            // 读取执行结果
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append("\
");
            }
            return result.toString();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // 模拟系统脚本
    static {
        try {
            File tempScript = File.createTempFile("export_data", ".sh");
            tempScript.setExecutable(true);
            try (FileWriter writer = new FileWriter(tempScript)) {
                writer.write("#!/bin/bash\
echo \\"Exporting data to $1\\"\
");
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}