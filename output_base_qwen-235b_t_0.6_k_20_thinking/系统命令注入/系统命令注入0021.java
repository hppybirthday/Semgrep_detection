package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@SpringBootApplication
@RestController
@RequestMapping("/api/files")
public class FileProcessor {

    public static void main(String[] args) {
        SpringApplication.run(FileProcessor.class, args);
    }

    @GetMapping("/process")
    public String processFile(@RequestParam String fileName) {
        StringBuilder output = new StringBuilder();
        Process process = null;
        
        try {
            // 漏洞点：直接拼接用户输入到系统命令中
            String[] cmd = {"/bin/sh", "-c", "cat /data/files/" + fileName};
            process = Runtime.getRuntime().exec(cmd);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
        } catch (IOException e) {
            output.append("Error processing file: ").append(e.getMessage());
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
        
        return output.toString();
    }
}

// pom.xml dependencies:
// <dependency>
//     <groupId>org.springframework.boot</groupId>
//     <artifactId>spring-boot-starter-web</artifactId>
// </dependency>