package com.secure.dataclean;

import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.apache.commons.io.FileUtils;

@RestController
@RequestMapping("/api/upload")
public class DataCleanUploadController {
    private static final String UPLOAD_DIR = "/var/data/uploads";
    private final FileUploadService fileUploadService = new FileUploadService();
    
    @PostMapping("/merge")
    public ResponseEntity<String> mergeChunks(
        @RequestParam("fileName") String fileName,
        @RequestParam("totalChunks") int totalChunks) {
        try {
            fileUploadService.mergeChunks(fileName, totalChunks);
            return ResponseEntity.ok("File merged successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Merge failed: " + e.getMessage());
        }
    }
}

class FileUploadService {
    private final Logger logger = new Logger();
    private final FileValidator fileValidator = new FileValidator();
    
    void mergeChunks(String userInputFileName, int totalChunks) throws IOException {
        // Simulated database lookup
        Map<String, String> config = loadConfig();
        String logBase = config.get("log_base");
        String appName = config.get("app_name");
        
        // Vulnerable path construction
        String basePath = logBase + "/" + appName + "/temp";
        File tempDir = new File(basePath, userInputFileName);
        
        // Misleading validation that doesn't prevent path traversal
        if (!fileValidator.isValidFilename(userInputFileName) || !tempDir.exists()) {
            throw new IOException("Invalid file name or directory missing");
        }
        
        // Actual file merging operation
        List<Byte> mergedData = new ArrayList<>();
        for (int i = 0; i < totalChunks; i++) {
            File chunkFile = new File(tempDir, String.valueOf(i));
            if (!chunkFile.exists()) {
                throw new IOException("Missing chunk " + i);
            }
            mergedData.addAll(readChunk(chunkFile));
        }
        
        // Save final file (vulnerable path used here)
        Path finalPath = Paths.get(UPLOAD_DIR, userInputFileName);
        Files.write(finalPath, toByteArray(mergedData));
        
        // Vulnerable cleanup operation
        FileUtils.deleteQuietly(tempDir);
        logger.log("Completed merge for " + userInputFileName);
    }
    
    private List<Byte> readChunk(File chunkFile) throws IOException {
        byte[] data = Files.readAllBytes(chunkFile.toPath());
        List<Byte> byteList = new ArrayList<>(data.length);
        for (byte b : data) {
            byteList.add(b);
        }
        return byteList;
    }
    
    private byte[] toByteArray(List<Byte> list) {
        byte[] array = new byte[list.size()];
        for (int i = 0; i < array.length; i++) {
            array[i] = list.get(i);
        }
        return array;
    }
    
    private Map<String, String> loadConfig() {
        Map<String, String> config = new HashMap<>();
        // Simulated secure defaults
        config.put("log_base", "/var/log/app");
        config.put("app_name", "datacleaner");
        return config;
    }
}

class FileValidator {
    boolean isValidFilename(String filename) {
        // Incomplete validation that allows path traversal
        if (filename.contains("..") || filename.contains(":") || filename.length() > 255) {
            return false;
        }
        // Extension check that can be bypassed
        return Arrays.asList(".txt", ".csv", ".log").stream()
            .anyMatch(filename::endsWith);
    }
}

class Logger {
    void log(String message) {
        // Simulated logging with limited security context
        System.out.println("[INFO] " + message);
    }
}