package com.example.vulnerableapp;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.*;
import java.util.concurrent.*;
import java.util.stream.*;

@RestController
@RequestMapping("/files")
public class FileController {
    
    @GetMapping("/list")
    public String listFiles(@RequestParam String dir) {
        try {
            // 漏洞点：直接将用户输入拼接到命令中
            String command = "ls -la " + dir;
            ProcessBuilder builder = new ProcessBuilder("/bin/sh", "-c", command);
            builder.redirectErrorStream(true);
            Process process = builder.start();
            
            // 读取命令输出
            CompletableFuture<String> output = CompletableFuture.supplyAsync(() -> {
                try (BufferedReader reader = new BufferedReader(
                     new InputStreamReader(process.getInputStream()))) {
                    return reader.lines().collect(Collectors.joining("\
"));
                } catch (IOException e) {
                    return "Error reading output";
                }
            });
            
            process.waitFor(10, TimeUnit.SECONDS);
            return output.get();
            
        } catch (Exception e) {
            return "Error executing command: " + e.getMessage();
        }
    }
    
    @GetMapping("/exists")
    public String checkFileExists(@RequestParam String filename) {
        try {
            // 更危险的漏洞写法
            Process process = Runtime.getRuntime().exec(
                new String[]{"/bin/sh", "-c", "test -f " + filename + " && echo 'Exists' || echo 'Not found'"}
            );
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream())
            );
            
            return reader.lines().collect(Collectors.joining("\
"));
            
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}