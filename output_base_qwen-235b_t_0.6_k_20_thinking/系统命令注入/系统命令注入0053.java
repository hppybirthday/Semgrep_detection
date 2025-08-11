package com.example.vulnerableapi;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@SpringBootApplication
public class VulnerableApiApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableApiApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/files")
class FileController {
    
    @GetMapping("/content")
    public String getFileContent(@RequestParam String filename) {
        StringBuilder output = new StringBuilder();
        try {
            // 漏洞点：直接拼接用户输入到系统命令
            Process process = Runtime.getRuntime().exec("cat " + filename);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            if (exitCode != 0) {
                return "Error reading file: Exit code " + exitCode;
            }
            
        } catch (IOException | InterruptedException e) {
            return "Error: " + e.getMessage();
        }
        
        return output.toString();
    }
}

// 服务层模拟
interface FileService {
    String readFile(String path);
}

class UnixFileService implements FileService {
    public String readFile(String path) {
        // 模拟底层调用
        return "File content for " + path;
    }
}