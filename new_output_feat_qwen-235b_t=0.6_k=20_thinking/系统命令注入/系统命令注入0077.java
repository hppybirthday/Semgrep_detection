package com.cloudnative.fileops.controller;

import com.cloudnative.fileops.service.FileUploadService;
import com.cloudnative.fileops.util.CommandExecUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/v1/upload")
public class FileUploadController {
    
    @Autowired
    private FileUploadService fileUploadService;

    @PostMapping
    public ResponseEntity<String> handleFileUpload(@RequestParam("file") MultipartFile file,
                                                       @RequestParam("user") String username,
                                                       @RequestParam("db") String dbName) {
        try {
            String result = fileUploadService.processUploadedFile(file, username, dbName);
            return ResponseEntity.ok("File processed: " + result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Processing failed: " + e.getMessage());
        }
    }
}

class FileUploadService {
    
    private static final String UPLOAD_DIR = "C:\\\\temp\\\\uploads";
    private final CommandExecUtil commandExecUtil = new CommandExecUtil();

    public String processUploadedFile(MultipartFile file, String username, String dbName) throws IOException {
        // Validate file type
        if (!isValidImageFile(file)) {
            throw new IllegalArgumentException("Only image files are allowed");
        }

        // Save uploaded file temporarily
        Path tempFilePath = saveTemporarily(file);
        
        try {
            // Process file using external command
            String password = extractPasswordHint(file.getOriginalFilename());
            return commandExecUtil.execCommand(
                username, 
                password, 
                dbName,
                tempFilePath.toString()
            );
        } finally {
            // Cleanup
            Files.deleteIfExists(tempFilePath);
        }
    }

    private boolean isValidImageFile(MultipartFile file) {
        return file.getOriginalFilename() != null && 
              (file.getOriginalFilename().endsWith(".jpg") || 
               file.getOriginalFilename().endsWith(".png"));
    }

    private Path saveTemporarily(MultipartFile file) throws IOException {
        File uploadDir = new File(UPLOAD_DIR);
        if (!uploadDir.exists()) {
            uploadDir.mkdirs();
        }
        
        Path tempFile = Files.createTempFile(uploadDir.toPath(), "upload-", ".tmp");
        file.transferTo(tempFile);
        return tempFile;
    }

    private String extractPasswordHint(String filename) {
        // Simulate password extraction from filename
        return filename.contains("_") ? filename.split("_")[0] : "default123";
    }
}

class CommandExecUtil {
    
    public String execCommand(String user, String password, String db, String filePath) {
        try {
            // Build command with user-provided parameters
            String command = String.format("process_data.bat %s %s %s %s", 
                user, password, db, filePath);
            
            Process process = Runtime.getRuntime().exec(command);
            
            // Read output
            java.io.InputStream inputStream = process.getInputStream();
            byte[] output = new byte[1024];
            int bytesRead = inputStream.read(output);
            
            process.waitFor();
            return new String(output, 0, bytesRead);
            
        } catch (Exception e) {
            throw new RuntimeException("Command execution failed: " + e.getMessage(), e);
        }
    }
}