package com.example.demo.controller;

import org.springframework.web.bind.annotation.*;
import java.io.*;

@RestController
@RequestMapping("/api")
public class FileSearchController {
    
    @GetMapping("/search")
    public String searchFiles(@RequestParam String directory) {
        try {
            // 构造命令数组（存在漏洞的拼接方式）
            String[] cmd = new String[3];
            cmd[0] = "sh";
            cmd[1] = "-c";
            cmd[2] = "find " + directory + " -type f -name \\"*.log\\"";
            
            Process process = Runtime.getRuntime().exec(cmd);
            
            // 读取命令执行输出
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            // 等待进程结束
            int exitCode = process.waitFor();
            return "Exit Code: " + exitCode + "\
Output:\
" + output.toString();
            
        } catch (Exception e) {
            return "Error executing command: " + e.getMessage();
        }
    }
    
    @GetMapping("/ping")
    public String pingHost(@RequestParam String host) {
        try {
            // 存在漏洞的拼接方式
            String[] cmd = {"ping", "-c", "4", host};
            Process process = Runtime.getRuntime().exec(cmd);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            return output.toString();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // 模拟日志处理的辅助类（与漏洞无关）
    static class LogProcessor {
        public String processLog(String content) {
            // 模拟日志处理逻辑
            return content.replaceAll("(\\\\d+)\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+", "[IP_HIDDEN]");
        }
    }
}