package com.example.vulnerableapp;

import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.Arrays;

@RestController
@RequestMapping("/files")
public class FileDownloadController {
    private static final String BASE_DIR = "/var/www/uploads/";

    @GetMapping("/download")
    public ResponseEntity<byte[]> downloadFile(@RequestParam("filename") String filename) throws IOException {
        File file = new File(BASE_DIR + filename);
        
        if (!file.exists()) {
            throw new RuntimeException("File not found");
        }

        byte[] content = Files.readAllBytes(file.toPath());
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.setContentDispositionFormData("attachment", filename);
        
        return ResponseEntity.ok()
                .headers(headers)
                .body(content);
    }

    // Simulated admin endpoint for demo purposes
    @GetMapping("/admin/config")
    public String adminConfig() {
        return "Admin config: super_secret_key=123456";
    }

    public static void main(String[] args) {
        // Simulated file structure
        System.out.println("Creating simulated files...");
        try {
            Files.createDirectories(new File(BASE_DIR).toPath());
            Files.write(new File(BASE_DIR + "test.txt").toPath(), "Sample content".getBytes());
            
            // Create sensitive file outside base dir
            File sensitiveFile = new File("/var/www/config.txt");
            sensitiveFile.getParentFile().mkdirs();
            Files.write(sensitiveFile.toPath(), "TOP_SECRET_DATA".getBytes());
            
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}