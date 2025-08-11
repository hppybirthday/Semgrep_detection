package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

@SpringBootApplication
public class FileServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(FileServiceApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/files")
class FileController {
    private final FileService fileService;

    public FileController(FileService fileService) {
        this.fileService = fileService;
    }

    @GetMapping("/{filename}")
    public ResponseEntity<String> getFileContent(@PathVariable String filename) {
        try {
            String content = fileService.readSecureFile(filename);
            return ResponseEntity.ok(content);
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Error reading file");
        }
    }
}

class FileService {
    private static final String BASE_PATH = "/var/www/html/files/";

    public String readSecureFile(String filename) throws IOException {
        // Vulnerable code: directly concatenating user input with base path
        File file = new File(BASE_PATH + filename);
        
        // Security check bypassed by path traversal
        if (!file.getAbsolutePath().startsWith(BASE_PATH)) {
            throw new SecurityException("Access denied");
        }

        // Vulnerable to path traversal due to incorrect path validation
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            return new String(data);
        }
    }
}

// SecurityBypassExplanation:
// 1. The path validation check can be bypassed using encoded path traversal
// 2. Example: "/api/files/..%2f..%2fetc%2fpasswd" will resolve to "/var/www/html/files/../etc/passwd"
// 3. The getAbsolutePath() will normalize the path but the validation check is flawed