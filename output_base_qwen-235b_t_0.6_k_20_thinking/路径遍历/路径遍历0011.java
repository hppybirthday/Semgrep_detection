package com.bank.file;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.nio.file.*;
import java.util.Base64;

@SpringBootApplication
public class FileApplication {
    public static void main(String[] args) {
        SpringApplication.run(FileApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/v1/files")
class FileController {
    private final FileService fileService = new FileService();

    @GetMapping("/download")
    public ResponseEntity<String> downloadFile(@RequestParam String filename) {
        try {
            String content = fileService.readFile(filename);
            return ResponseEntity.ok(content);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error reading file");
        }
    }

    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(@RequestParam String filename, @RequestBody String content) {
        try {
            fileService.writeFile(filename, content);
            return ResponseEntity.ok("File saved successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error writing file");
        }
    }
}

class FileService {
    private static final String BASE_DIR = "/var/bank_data/customer_files/";

    public String readFile(String filename) throws IOException {
        Path filePath = Paths.get(BASE_DIR + filename);
        if (!filePath.normalize().startsWith(BASE_DIR)) {
            throw new SecurityException("Invalid file path");
        }
        return new String(Files.readAllBytes(filePath));
    }

    public void writeFile(String filename, String content) throws IOException {
        Path filePath = Paths.get(BASE_DIR + filename);
        if (!filePath.normalize().startsWith(BASE_DIR)) {
            throw new SecurityException("Invalid file path");
        }
        Files.write(filePath, content.getBytes(), StandardOpenOption.CREATE);
    }
}