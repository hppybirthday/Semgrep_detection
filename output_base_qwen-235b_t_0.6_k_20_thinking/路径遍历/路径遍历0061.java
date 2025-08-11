package com.example.mathsim;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.stream.*;

@SpringBootApplication
@RestController
@RequestMapping("/api/sim")
public class PathTraversalVuln {
    private static final String BASE_DIR = "/var/math_models/";

    @GetMapping("/run")
    public String runSimulation(@RequestParam String modelFile) {
        try {
            String fullPath = BASE_DIR + modelFile;
            File file = new File(fullPath);
            if (!file.exists()) {
                return "Model file not found";
            }
            
            // Vulnerable path traversal
            if (!file.getCanonicalPath().startsWith(new File(BASE_DIR).getCanonicalPath())) {
                return "Access denied: Attempted path traversal";
            }
            
            // Simulate model loading
            String content = Files.readLines(file, java.nio.charset.StandardCharsets.UTF_8)
                .stream().limit(10).collect(Collectors.joining("\
"));
            
            return "Loaded model: " + modelFile + "\
Preview: " + content;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // Simulated model execution endpoint
    @PostMapping("/execute")
    public String executeModel(@RequestParam String configFile) {
        try {
            ProcessBuilder pb = new ProcessBuilder("/usr/bin/python3", "-c", "import numpy as np; print(np.__version__)");
            Process process = pb.start();
            String output = readStream(process.getInputStream());
            return "Model executed successfully. NumPy version: " + output;
        } catch (Exception e) {
            return "Execution failed: " + e.getMessage();
        }
    }

    private String readStream(InputStream stream) throws IOException {
        return new BufferedReader(new InputStreamReader(stream))
            .lines().collect(Collectors.joining("\
"));
    }

    public static void main(String[] args) {
        SpringApplication.run(PathTraversalVuln.class, args);
    }
}