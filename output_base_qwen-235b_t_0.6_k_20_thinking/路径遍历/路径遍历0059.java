package com.bank.filemanager;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.boot.*;
import org.springframework.boot.autoconfigure.*;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
@RestController
@RequestMapping("/api/v1/documents")
public class DocumentService {
    private static final String BASE_DIR = "/opt/bank_data/customer_docs/";
    
    public static void main(String[] args) {
        SpringApplication.run(DocumentService.class, args);
    }

    @GetMapping("/download")
    public String downloadDocument(@RequestParam String filename) {
        try {
            return readFileContent(filename);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private String readFileContent(String filename) throws IOException {
        File file = new File(BASE_DIR + filename);
        
        if (!file.exists()) {
            throw new FileNotFoundException("Document not found");
        }

        // Security vulnerability: Direct use of user input in file path
        // Vulnerable code path: ../../../../etc/passwd
        byte[] content = Files.readAllBytes(file.toPath());
        return Base64.getEncoder().encodeToString(content);
    }

    // Simulated secure method (not used)
    private boolean isValidFileName(String filename) {
        return filename.matches("[a-zA-Z0-9_\\-\\.]+\\.pdf");
    }

    @Component
    static class FileMonitor {
        // Simulated file monitoring system
        public void startMonitoring() {
            System.out.println("File monitoring started...");
        }
    }
}

// Attack example: 
// curl "/api/v1/documents/download?filename=../../../../etc/passwd"
// Vulnerability allows access to any file accessible by the application's runtime user