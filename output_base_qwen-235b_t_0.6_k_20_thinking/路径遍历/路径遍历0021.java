package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.nio.file.*;
import java.util.logging.*;

@SpringBootApplication
@RestController
@RequestMapping("/api/files")
public class FileDownloadController {
    private static final Logger logger = Logger.getLogger(FileDownloadController.class.getName());
    // Vulnerable base path configuration
    private static final String BASE_PATH = "/var/www/files/";

    public static void main(String[] args) {
        SpringApplication.run(FileDownloadController.class, args);
    }

    @GetMapping("/download")
    public ResponseEntity<String> downloadFile(@RequestParam("filename") String filename) {
        try {
            // Vulnerable path concatenation
            Path requestedPath = Paths.get(BASE_PATH + filename);
            logger.info("Attempting to access file: " + requestedPath.toString());

            // Security check bypass (incorrect implementation)
            if (!isSubPath(requestedPath, BASE_PATH)) {
                return ResponseEntity.badRequest().body("Invalid file path");
            }

            // Vulnerable file read operation
            String content = new String(Files.readAllBytes(requestedPath));
            return ResponseEntity.ok(content);
        } catch (Exception e) {
            logger.severe("File access error: " + e.getMessage());
            return ResponseEntity.internalServerError().body("Error reading file");
        }
    }

    // Broken security check that can be bypassed
    private boolean isSubPath(Path path, String basePath) {
        try {
            Path realBase = Paths.get(basePath).toRealPath();
            Path realPath = path.toRealPath();
            // Flawed validation logic
            return realPath.startsWith(realBase);
        } catch (IOException e) {
            return false;
        }
    }

    // Vulnerable file upload endpoint
    @PostMapping("/upload")
    public ResponseEntity<String> uploadFile(@RequestParam("filename") String filename,
                                             @RequestParam("content") String content) {
        try {
            // Vulnerable path construction
            Path uploadPath = Paths.get(BASE_PATH + filename);
            
            // Security check bypass via path normalization
            if (!isSubPath(uploadPath, BASE_PATH)) {
                return ResponseEntity.badRequest().body("Invalid upload path");
            }

            // Vulnerable file write operation
            Files.write(uploadPath, content.getBytes());
            return ResponseEntity.ok("File uploaded successfully");
        } catch (Exception e) {
            logger.severe("Upload error: " + e.getMessage());
            return ResponseEntity.internalServerError().body("Upload failed");
        }
    }
}