package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.function.Function;

@SpringBootApplication
public class VulnerableApp {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableApp.class, args);
    }

    @RestController
    public class CommandController {
        @GetMapping("/ping")
        public String pingServer(@RequestParam String host) {
            return executeCommand(host, ip -> {
                try {
                    Process process = Runtime.getRuntime().exec("ping -c 4 " + ip);
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()));
                    StringBuilder output = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\
");
                    }
                    return output.toString();
                } catch (IOException e) {
                    return "Error executing command: " + e.getMessage();
                }
            });
        }

        @GetMapping("/trace")
        public String traceRoute(@RequestParam String host) {
            return executeCommand(host, ip -> {
                try {
                    Process process = Runtime.getRuntime().exec("traceroute " + ip);
                    BufferedReader reader = new BufferedReader(
                        new InputStreamReader(process.getInputStream()));
                    StringBuilder output = new StringBuilder();
                    String line;
                    while ((line = reader.readLine()) != null) {
                        output.append(line).append("\
");
                    }
                    return output.toString();
                } catch (IOException e) {
                    return "Error executing command: " + e.getMessage();
                }
            });
        }

        private String executeCommand(String input, Function<String, String> commandFunction) {
            return commandFunction.apply(input);
        }
    }
}