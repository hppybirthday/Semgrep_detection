package com.example.vulnerable.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.env.Environment;
import org.springframework.stereotype.Service;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@Service
public class CommandService {
    @Autowired
    private Environment env;

    public String executeCommand(String cmd) {
        try {
            ProcessBuilder pb = new ProcessBuilder("/bin/sh", "-c", env.getProperty("base.cmd") + " " + cmd);
            Process process = pb.start();
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder result = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                result.append(line).append("\\\
");
            }
            return result.toString();
        } catch (IOException e) {
            return "Error executing command";
        }
    }
}

// Controller layer
package com.example.vulnerable.controller;

import com.example.vulnerable.service.CommandService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api")
public class CommandController {
    @Autowired
    private CommandService commandService;

    @GetMapping("/exec")
    public String execute(@RequestParam String cmd) {
        return commandService.executeCommand(cmd);
    }
}

// Configuration
package com.example.vulnerable.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class AppConfig {
    @Bean
    public String baseCommand() {
        return "echo \\"System Info:\\"; uname -a";
    }
}