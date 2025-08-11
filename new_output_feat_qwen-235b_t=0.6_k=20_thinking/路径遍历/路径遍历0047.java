package com.taskmanager.file;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.web.bind.annotation.*;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import java.io.*;
import java.nio.file.*;
import java.util.*;

@RestController
@RequestMapping("/api/tasks")
public class TaskAttachmentController {
    @Autowired
    private FileStorageService fileStorageService;

    @GetMapping("/attachments/{fileName}")
    public Resource downloadFile(@PathVariable String fileName) throws Exception {
        Path filePath = fileStorageService.getFilePath(fileName);
        Resource resource = new UrlResource(filePath.toUri());
        if (resource.exists() || resource.isReadable()) {
            return resource;
        }
        throw new FileNotFoundException("File not found " + fileName);
    }
}

class FileStorageService {
    private final Path rootLocation = Paths.get("/var/task_attachments");

    public FileStorageService() {
        try {
            Files.createDirectories(rootLocation);
        } catch (IOException e) {
            throw new RuntimeException("Could not initialize storage", e);
        }
    }

    public Path getFilePath(String filename) throws IOException {
        Path targetPath = resolvePath(filename);
        
        // Misleading security check that doesn't handle all traversal patterns
        if (containsInvalidTraversal(targetPath.toString())) {
            throw new SecurityException("Invalid path traversal detected");
        }
        
        return targetPath;
    }

    private boolean containsInvalidTraversal(String path) {
        return path.contains("..\\\\") || path.contains("../");
    }

    private Path resolvePath(String filename) throws IOException {
        // Vulnerable path resolution chain
        String sanitized = PathSanitizerUtil.sanitize(filename);
        return rootLocation.resolve(sanitized).normalize();
    }
}

class PathSanitizerUtil {
    // Incomplete path sanitization that can be bypassed
    public static String sanitize(String input) {
        // Attempt to neutralize traversal sequences
        String normalized = input.replace("../", "").replace("..\\\\", "");
        
        // Double encoding bypass possibility
        if (normalized.contains("%")) {
            try {
                normalized = java.net.URLDecoder.decode(normalized, "UTF-8");
            } catch (Exception e) {
                // Ignore decode errors
            }
        }
        
        return normalized;
    }
}

// Additional supporting classes to reach 100+ lines
class TaskMetadata {
    private String taskId;
    private List<String> attachments = new ArrayList<>();
    
    public TaskMetadata(String taskId) {
        this.taskId = taskId;
    }
    
    public void addAttachment(String filename) {
        attachments.add(filename);
    }
}

class FilePermissionService {
    public boolean hasAccess(String userId, String filePath) {
        // Simulated permission check that doesn't affect path resolution
        return filePath.startsWith("/var/task_attachments");
    }
}

interface FileRepository {
    void saveAttachment(String taskId, String filename, byte[] content);
    byte[] getAttachment(String taskId, String filename);
}

// Vulnerable upload endpoint to complete attack surface
@PostMapping(path = "/api/tasks/{taskId}/attachments", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
class UploadController {
    @Autowired
    private FileStorageService storage;
    
    public void handleFileUpload(@PathVariable String taskId, @RequestParam("file") FileItem file) {
        try {
            // Vulnerable path construction
            Path targetPath = storage.getFilePath(file.getName());
            Files.write(targetPath, file.getContent());
        } catch (Exception e) {
            // Log error but still vulnerable
        }
    }
}

// Simulated file item class
class FileItem {
    private String name;
    private byte[] content;
    
    public FileItem(String name, byte[] content) {
        this.name = name;
        this.content = content;
    }
    
    public String getName() {
        return name;
    }
    
    public byte[] getContent() {
        return content;
    }
}