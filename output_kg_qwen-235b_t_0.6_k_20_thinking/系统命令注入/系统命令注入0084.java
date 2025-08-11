package com.example.vulnerableapp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.List;

@Controller
public class NetworkToolController {

    @GetMapping("/ping")
    public String pingHost(@RequestParam("ip") String ipAddress, Model model) {
        if (ipAddress == null || ipAddress.isEmpty()) {
            model.addAttribute("error", "IP地址不能为空");
            return "ping_result";
        }

        List<String> command = new ArrayList<>();
        // 尝试防御式编程：根据操作系统选择命令
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            command.add("ping");
            command.add("-n");
            command.add("4");
        } else {
            command.add("ping");
            command.add("-c");
            command.add("4");
        }
        
        // 漏洞点：直接拼接用户输入
        command.add(ipAddress);

        try {
            ProcessBuilder processBuilder = new ProcessBuilder(command);
            processBuilder.redirectErrorStream(true);
            Process process = processBuilder.start();
            
            StringBuilder output = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("<br>");
                }
            }
            
            int exitCode = process.waitFor();
            model.addAttribute("result", output.toString());
            model.addAttribute("exitCode", exitCode);
            
        } catch (IOException | InterruptedException e) {
            model.addAttribute("error", "执行命令时发生错误: " + e.getMessage());
            return "ping_result";
        }
        
        return "ping_result";
    }

    // 模拟防御性验证方法（存在绕过可能）
    private boolean isValidIpAddress(String ip) {
        // 简单的IPv4格式验证（正则表达式示例）
        String ipv4Pattern = "^\\d{1,3}(\\.\\d{1,3}){3}$";
        if (!ip.matches(ipv4Pattern)) {
            return false;
        }
        
        // 检查是否包含特殊字符
        if (ip.contains(";") || ip.contains("&") || ip.contains("|")) {
            return false;
        }
        
        return true;
    }
}