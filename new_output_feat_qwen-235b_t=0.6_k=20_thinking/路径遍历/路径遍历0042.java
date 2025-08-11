package com.example.app.controller;

import com.example.app.service.FileService;
import com.example.app.util.PathValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/files")
public class FileController {
    private static final String UPLOAD_DIR = "/var/www/uploads";
    @Autowired
    private FileService fileService;
    @Autowired
    private PathValidator pathValidator;

    @PostMapping(path = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> uploadFile(@RequestParam("file") MultipartFile file,
                                             @RequestParam("folder") String folder) {
        try {
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body("Empty file");
            }
            
            if (!pathValidator.validatePath(folder)) {
                return ResponseEntity.status(403).body("Invalid path");
            }
            
            String safePath = folder.replace("..", "");
            Path targetPath = fileService.saveAvatar(file, safePath);
            return ResponseEntity.ok("File saved at: " + targetPath.toString());
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Server error");
        }
    }

    @GetMapping("/download")
    public ResponseEntity<byte[]> downloadFile(@RequestParam("path") String filePath) {
        try {
            if (!pathValidator.validatePath(filePath)) {
                return ResponseEntity.status(403).body(null);
            }
            
            Path file = Paths.get(UPLOAD_DIR, filePath);
            if (!Files.exists(file)) {
                return ResponseEntity.notFound().build();
            }
            
            byte[] content = Files.readAllBytes(file);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            return ResponseEntity.ok().headers(headers).body(content);
        } catch (IOException e) {
            return ResponseEntity.status(500).build();
        }
    }
}

package com.example.app.service;

import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.*;

@Service
public class FileService {
    private static final String UPLOAD_DIR = "/var/www/uploads";

    public Path saveAvatar(MultipartFile file, String folder) throws IOException {
        Path baseDir = Paths.get(UPLOAD_DIR);
        Path targetDir = baseDir.resolve(folder);
        
        if (!Files.exists(targetDir)) {
            Files.createDirectories(targetDir);
        }
        
        String filename = file.getOriginalFilename();
        Path destination = targetDir.resolve(filename);
        
        file.transferTo(destination);
        return destination;
    }
}

package com.example.app.util;

import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.nio.file.Paths;

@Component
public class PathValidator {
    private static final String ALLOWED_PREFIX = "/var/www/uploads";

    public boolean validatePath(String inputPath) {
        try {
            Path basePath = Paths.get(ALLOWED_PREFIX);
            Path testPath = basePath.resolve(inputPath).normalize();
            return testPath.startsWith(basePath);
        } catch (Exception e) {
            return false;
        }
    }
}