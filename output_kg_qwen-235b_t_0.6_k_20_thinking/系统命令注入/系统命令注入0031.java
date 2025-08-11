package com.example.vulnerablemicroservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;

@SpringBootApplication
@RestController
@RequestMapping("/api/v1")
public class FileServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(FileServiceApplication.class, args);
    }

    @GetMapping("/files/content")
    public String getFileContent(@RequestParam String filename) {
        StringBuilder output = new StringBuilder();
        ProcessBuilder processBuilder = new ProcessBuilder();
        
        try {
            // 漏洞点：直接拼接用户输入到命令中
            String[] cmd;
            if (System.getProperty("os.name").toLowerCase().contains("win")) {
                cmd = new String[]{"cmd.exe", "/c", "type " + filename};
            } else {
                cmd = new String[]{"sh", "-c", "cat " + filename};
            }
            
            Process process = processBuilder.command(cmd).start();
            
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                 BufferedReader errorReader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream()))) {
                
                String line;
                while ((line = reader.readLine()) != null) {
                    output.append(line).append("\
");
                }
                
                while ((line = errorReader.readLine()) != null) {
                    output.append("ERROR: ").append(line).append("\
");
                }
            }
            
        } catch (IOException e) {
            output.append("Error executing command: ").append(e.getMessage());
        }
        
        return output.toString();
    }

    @PostMapping("/system/backup")
    public String createBackup(@RequestParam String sourceDir, 
                              @RequestParam String targetDir) {
        try {
            // 漏洞点：双重命令注入风险
            String command = String.format("cp -r %s %s", sourceDir, targetDir);
            Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
            return "Backup started: " + command;
        } catch (IOException e) {
            return "Backup failed: " + e.getMessage();
        }
    }

    @GetMapping("/health/check")
    public String checkHealth(@RequestParam String host) {
        try {
            // 漏洞点：主机名参数注入
            Process process = new ProcessBuilder()
                .command(Arrays.asList("ping", "-c", "4", host))
                .start();
            return "Ping initiated to " + host;
        } catch (IOException e) {
            return "Health check failed: " + e.getMessage();
        }
    }
}