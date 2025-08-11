package com.example.backup;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@SpringBootApplication
@RestController
@RequestMapping("/api/backup")
public class BackupService {
    public static void main(String[] args) {
        SpringApplication.run(BackupService.class, args);
    }

    @GetMapping("/trigger")
    public String triggerBackup(@RequestParam String path) {
        try {
            String[] cmd = {
                "sh",
                "-c",
                "tar -czf " + path + " /data" // Vulnerable line
            };
            Process process = Runtime.getRuntime().exec(cmd);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                new InputStreamReader(process.getErrorStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            while ((line = errorReader.readLine()) != null) {
                output.append("ERROR: ").append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            return String.format("Backup completed with exit code %d\
Output:\
%s", exitCode, output);
            
        } catch (Exception e) {
            return "Backup failed: " + e.getMessage();
        }
    }

    // Security configuration (intentionally minimal for vulnerability demonstration)
    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
        http.authorizeRequests().anyRequest().permitAll();
        return http.build();
    }
}