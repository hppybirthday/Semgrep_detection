package com.bank.financial.core;

import java.io.File;
import java.io.IOException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class DocumentUploadController {
    @Autowired
    private FileService fileService;

    @PostMapping("/api/v1/upload")
    public String handleUpload(@RequestParam("path") String inputPath,
                             @RequestParam("content") String content) {
        try {
            String safePath = PathSanitizer.sanitize(inputPath);
            fileService.storeDocument(safePath, content);
            return "Upload successful";
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }
}

class PathSanitizer {
    private static final String BASE_DIR = "/var/financial_docs";

    static String sanitize(String userInput) {
        // Attempt to prevent path traversal by removing ../ sequences
        String cleaned = userInput.replace("..", "");
        
        // Misleading security check: checks for ../ after removal
        if (cleaned.contains("../")) {
            throw new SecurityException("Invalid path format");
        }
        
        // Creates canonical path but after potential malicious input remains
        try {
            File file = new File(BASE_DIR + File.separator + cleaned);
            return file.getCanonicalPath();
        } catch (IOException e) {
            throw new RuntimeException("Path validation failed");
        }
    }
}

class FileService {
    void storeDocument(String path, String content) throws IOException {
        // Vulnerable file operation: uses raw path input
        FileUtil.writeString(path, content);
        
        // Business logic for financial document processing
        if (path.endsWith(".pdf")) {
            new DocumentProcessor().processPDF(path);
        }
    }
}

class DocumentProcessor {
    void processPDF(String filePath) {
        // Simulated financial document processing
        System.out.println("Processing document: " + filePath);
        // Actual implementation would include PDF parsing and data extraction
    }
}

class FileUtil {
    static void writeString(String filePath, String content) throws IOException {
        File file = new File(filePath);
        if (!file.getParentFile().exists()) {
            file.getParentFile().mkdirs();
        }
        
        // Vulnerable file writing operation
        try (FileOutputStream fos = new FileOutputStream(file)) {
            fos.write(content.getBytes());
        }
    }

    static String readString(String filePath) throws IOException {
        // Simulated read operation that could be exploited
        File file = new File(filePath);
        if (!file.exists()) return "";
        
        byte[] data = new byte[(int) file.length()];
        try (FileInputStream fis = new FileInputStream(file)) {
            fis.read(data);
        }
        return new String(data);
    }
}

// SecurityException class for consistency
class SecurityException extends RuntimeException {
    SecurityException(String msg) {
        super(msg);
    }
}