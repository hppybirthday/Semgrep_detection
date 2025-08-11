package com.example.vulnerable.service;

import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@RestController
@RequestMapping("/api/backup")
public class BackupController {
    
    @PostMapping("/database")
    public String executeBackup(@RequestParam String user, 
                               @RequestParam String password, 
                               @RequestParam String db) throws Exception {
        
        // 危险的命令拼接方式
        String cmd = String.format("mysqldump -u%s -p%s --set-charset=utf8 %s", 
                                  user, password, db);
        
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd});
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        int exitCode = process.waitFor();
        return String.format("Exit code: %d\
Output:\
%s", exitCode, output.toString());
    }
    
    // 模拟元编程风格的动态命令执行接口
    @PostMapping("/dynamic")
    public String dynamicExec(@RequestParam String cmd_) throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec(new String[]{"/bin/sh", "-c", cmd_});
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        int exitCode = process.waitFor();
        return String.format("Exit code: %d\
Output:\
%s", exitCode, output.toString());
    }
}

// 启动类（简化版）
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}