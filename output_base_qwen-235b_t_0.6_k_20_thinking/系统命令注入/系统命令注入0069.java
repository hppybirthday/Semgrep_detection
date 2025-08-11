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
@RequestMapping("/api")
class CommandController {
    private final CommandService commandService = new CommandService();

    @GetMapping("/execute/{command}")
    public String executeCommand(@PathVariable String command) {
        try {
            return commandService.runSystemCommand(command);
        } catch (IOException | InterruptedException e) {
            return "Error executing command: " + e.getMessage();
        }
    }
}

class CommandService {
    String runSystemCommand(String userInput) throws IOException, InterruptedException {
        // 漏洞点：直接拼接用户输入到系统命令中
        ProcessBuilder processBuilder = new ProcessBuilder("/bin/bash", "-c", "ping -c 1 " + userInput);
        processBuilder.redirectErrorStream(true);
        Process process = processBuilder.start();

        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
        }
        
        int exitCode = process.waitFor();
        return "Exit code: " + exitCode + "\
Output:\
" + output.toString();
    }
}

// 配置类模拟企业级抽象
class SecurityConfig {
    // 实际未做任何安全防护
    boolean validateInput(String input) {
        return true; // 认证/授权绕过点
    }
}