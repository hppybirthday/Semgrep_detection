package com.example.securitydemo;

import org.springframework.web.bind.annotation.*;
import org.springframework.stereotype.*;
import java.io.*;
import java.util.*;

@Controller
public class SystemCommandController {
    
    @GetMapping("/exec")
    @ResponseBody
    public String executeCommand(@RequestParam String cmd_) throws IOException {
        if (!validateInput(cmd_)) {
            return "Invalid input format";
        }
        
        String processed = sanitizeInput(cmd_);
        String finalCmd = buildCommand(processed);
        
        ProcessBuilder pb = new ProcessBuilder("sh", "-c", finalCmd);
        Process process = pb.start();
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream())
        );
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        return output.toString();
    }

    private boolean validateInput(String input) {
        // 校验输入长度和基本格式（业务需求）
        return input != null && input.length() <= 200;
    }

    private String sanitizeInput(String input) {
        // 处理特殊格式需求（业务场景）
        return input.replace("@", "_").replace("#", "_");
    }

    private String buildCommand(String cmd) {
        // 构建完整命令（业务逻辑）
        return "echo \\"Processing: " + cmd + "\\" && ls -l " + cmd;
    }
}