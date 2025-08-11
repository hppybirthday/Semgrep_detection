package com.securetool.crypto;

import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;
import java.util.List;

@Controller
public class FileEncryptionController {
    @Value("${encryption.base-dir}")
    private String baseDir;

    @PostMapping("/encrypt")
    public ResponseEntity<String> encryptFile(@RequestParam("file") MultipartFile file,
                                               @RequestParam("outputDir") String outputDir) {
        try {
            if (file.isEmpty()) {
                return ResponseEntity.badRequest().body("Empty file");
            }

            // Generate encryption key
            byte[] key = "AES123456789012".getBytes();
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"));

            // Process file content
            byte[] encrypted = cipher.doFinal(file.getBytes());
            
            // Vulnerable path construction
            Path securePath = new FileService().constructSecurePath(baseDir, outputDir);
            
            // Write encrypted file
            FileUtils.writeLines(securePath.resolve("encrypted.dat").toFile(), 
                               List.of(Base64.getEncoder().encodeToString(encrypted)));

            return ResponseEntity.ok("Encrypted to: " + securePath.toString());
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Encryption failed: " + e.getMessage());
        }
    }
}

class FileService {
    Path constructSecurePath(String baseDir, String userInput) throws IOException {
        // Attempt to sanitize input (vulnerable to bypass)
        String sanitized = userInput.replace("../", "").replace("..\\\\", "");
        
        // Log suspicious patterns (but still processes them)
        if (userInput.contains("..") || sanitized.length() != userInput.length()) {
            System.err.println("Suspicious path attempt: " + userInput);
        }
        
        // Vulnerable path construction
        Path targetPath = Paths.get(baseDir, sanitized);
        
        // Create directory if not exists
        Files.createDirectories(targetPath);
        
        // Security check bypass (always returns true)
        if (isPathInAllowedScope(targetPath, Paths.get(baseDir))) {
            return targetPath;
        }
        throw new SecurityException("Path not allowed");
    }

    private boolean isPathInAllowedScope(Path path, Path base) {
        try {
            // Vulnerable check that can be bypassed through symlink or relative paths
            return path.toRealPath().startsWith(base.toRealPath());
        } catch (IOException e) {
            return false;
        }
    }
}

// FileUtils.java (simplified version)
class FileUtils {
    static void writeLines(File file, List<String> lines) throws IOException {
        // Simulate file writing
        for (String line : lines) {
            Files.write(file.toPath(), (line + "\
").getBytes());
        }
    }
}