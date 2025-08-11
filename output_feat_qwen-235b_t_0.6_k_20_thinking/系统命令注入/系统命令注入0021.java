package com.example.vulnerableapi;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.concurrent.*;

@RestController
@RequestMapping("/api")
public class CommandInjectionVuln {
    
    @GetMapping("/execute")
    public String executeCommand(@RequestParam String ip) {
        try {
            ProcessBuilder processBuilder = new ProcessBuilder();
            processBuilder.command("sh", "-c", "ping -c 4 " + ip);
            Process process = processBuilder.start();
            
            CompletableFuture<String> future = new CompletableFuture<>();
            new Thread(() -> {
                try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
                    BufferedWriter writer = new BufferedWriter(
                    new FileWriter("/tmp/command_output.log"))) {
                    
                    String line;
                    while ((line = reader.readLine()) != null) {
                        writer.write(line + "\
");
                    }
                    future.complete("Command executed successfully");
                } catch (Exception e) {
                    future.completeExceptionally(e);
                }
            }).start();
            
            String error = readStream(process.getErrorStream());
            int exitCode = process.waitFor();
            future.get(2, TimeUnit.SECONDS);
            
            return String.format("Exit code: %d\
Output: %s\
Error: %s",
                exitCode, readOutputFile(), error);
            
        } catch (Exception e) {
            return "Error executing command: " + e.getMessage();
        }
    }
    
    private String readStream(InputStream is) throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(is))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\
");
            }
        }
        return sb.toString();
    }
    
    private String readOutputFile() throws IOException {
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
             new FileReader("/tmp/command_output.log"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\
");
            }
        }
        return sb.toString();
    }
}