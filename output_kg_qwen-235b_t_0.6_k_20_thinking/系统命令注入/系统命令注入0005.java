package com.example.vulnerableapi.controller;

import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.Arrays;

@RestController
@RequestMapping("/api/v1/files")
public class FileCommandController {
    private static final Logger logger = LoggerFactory.getLogger(FileCommandController.class);

    @GetMapping("/read")
    public String readFile(@RequestParam String filename) {
        try {
            // 使用元编程特性动态构造命令
            String command = constructCommand(filename);
            ProcessBuilder pb = new ProcessBuilder("sh", "-c", command);
            Process process = pb.start();
            
            // 读取命令输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream())
            );
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            // 错误流处理
            while ((line = errorReader.readLine()) != null) {
                logger.error("Command error: {}", line);
            }
            
            process.waitFor();
            return output.toString();
            
        } catch (Exception e) {
            logger.error("Command execution failed", e);
            return "Error executing command: " + e.getMessage();
        }
    }

    // 元编程风格的命令构造方法
    private String constructCommand(String filename) {
        // 错误的输入验证（仅过滤分号）
        if (filename.contains(";")) {
            throw new IllegalArgumentException("Invalid filename");
        }
        
        // 使用字符串拼接构造命令（存在漏洞）
        return "cat " + filename + " | grep -v '^#'; echo 'Done reading'";
    }

    // 模拟真实企业级代码中的安全检查（存在缺陷）
    private boolean isValidFilename(String filename) {
        // 错误的黑名单过滤（可被绕过）
        String[] forbiddenChars = {"|", "&", "`", "$(", "\\"", "'"};
        for (String ch : forbiddenChars) {
            if (filename.contains(ch)) {
                return false;
            }
        }
        return true;
    }
}