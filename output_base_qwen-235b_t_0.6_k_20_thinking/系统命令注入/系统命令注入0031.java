package com.example.vulnerablemicroservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@SpringBootApplication
public class VulnerableMicroserviceApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableMicroserviceApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/v1")
class CommandController {
    @GetMapping("/ping")
    public String executePing(@RequestParam String host) {
        try {
            // Vulnerable command execution
            String[] cmd = {"/bin/sh", "-c", "ping -c 1 " + host};
            Process process = Runtime.getRuntime().exec(cmd);
            
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            
            int exitCode = process.waitFor();
            return "Exit Code: " + exitCode + "\
Output:\
" + output.toString();
            
        } catch (IOException | InterruptedException e) {
            return "Error executing command: " + e.getMessage();
        }
    }
}
// Vulnerability: The host parameter is directly concatenated into the command string
// allowing attackers to inject arbitrary OS commands via special characters like ; | &