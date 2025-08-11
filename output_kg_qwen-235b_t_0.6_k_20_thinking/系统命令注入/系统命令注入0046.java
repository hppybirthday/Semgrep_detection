package com.example.vulnerableapp;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;

@RestController
public class FileExplorer {
    @GetMapping("/list")
    public String listFiles(@RequestParam String path) {
        try {
            // 模拟移动应用后端需要执行系统命令的场景
            String[] cmd = new String[]{"/bin/sh", "-c", "ls -la " + path};
            Process process = Runtime.getRuntime().exec(cmd);
            
            // 异步读取输出流防止阻塞
            Future<String> output = Executors.newSingleThreadExecutor().submit(() -> {
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                StringBuilder result = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    result.append(line).append("\
");
                }
                return result.toString();
            });
            
            // 错误流合并到标准输出
            Future<String> error = Executors.newSingleThreadExecutor().submit(() -> {
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream()));
                StringBuilder result = new StringBuilder();
                String line;
                while ((line = reader.readLine()) != null) {
                    result.append(line).append("\
");
                }
                return result.toString();
            });
            
            // 超时处理
            process.waitFor(10, TimeUnit.SECONDS);
            return "STDOUT:\
" + output.get() + "\
STDERR:\
" + error.get();
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
    
    // 模拟文件上传后的病毒扫描功能
    @PostMapping("/scan")
    public String scanFile(@RequestParam String filename) {
        try {
            // 错误的参数处理方式
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", "clamscan " + filename);
            Process process = pb.start();
            
            // 简单的流处理
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
            return "Scan error: " + e.getMessage();
        }
    }
}
