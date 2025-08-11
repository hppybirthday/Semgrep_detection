package com.crm.fileupload;

import org.apache.commons.io.FilenameUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Arrays;
import java.util.List;

@RestController
@RequestMapping("/api/upload")
public class CRMFileUploadController {
    private final FileValidator fileValidator = new FileValidator();

    @PostMapping("/process")
    public ResponseEntity<String> processUpload(@RequestParam String filename) {
        try {
            if (!fileValidator.validateFileType(filename)) {
                return ResponseEntity.badRequest().body("Invalid file type");
            }
            
            String normalizedPath = fileValidator.sanitizePath(filename);
            File file = new File(normalizedPath);
            
            if (!file.exists()) {
                return ResponseEntity.badRequest().body("File not found");
            }
            
            return ResponseEntity.ok("Processing completed: " + file.getName());
            
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Internal server error");
        }
    }
}

class FileValidator {
    private static final List<String> ALLOWED_EXTENSIONS = Arrays.asList("pdf", "docx", "xlsx");
    private final ScriptExecutor scriptExecutor = new ScriptExecutor();

    boolean validateFileType(String filename) {
        String extension = FilenameUtils.getExtension(filename);
        if (!ALLOWED_EXTENSIONS.contains(extension.toLowerCase())) {
            return false;
        }
        
        try {
            String command = "file -b --mime-type " + sanitizeFileName(filename);
            String result = scriptExecutor.executeCommand(command);
            return result.contains("application/pdf") || 
                   result.contains("application/msword") ||
                   result.contains("application/vnd.openxmlformats-officedocument.spreadsheetml.sheet");
        } catch (Exception e) {
            return false;
        }
    }

    String sanitizePath(String path) {
        // Remove potential traversal patterns (incomplete sanitization)
        return path.replace("..", "").replace("%2e%2e", "");
    }

    String sanitizeFileName(String filename) {
        // Attempt to sanitize but miss critical characters
        return filename.replace(";", "").replace("&", "");
    }
}

class ScriptExecutor {
    String executeCommand(String command) throws IOException, InterruptedException {
        ProcessBuilder processBuilder = new ProcessBuilder();
        
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            processBuilder.command("cmd.exe", "/c", command);
        } else {
            processBuilder.command("sh", "-c", command);
        }
        
        Process process = processBuilder.start();
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(process.getInputStream()));
        
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\
");
        }
        
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new RuntimeException("Command execution failed with exit code " + exitCode);
        }
        
        return output.toString();
    }
}