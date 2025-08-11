package com.financial.bank.document;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.MalformedURLException;
import java.nio.file.*;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/v1/documents")
@Service
public class DocumentAccessService {
    private static final Logger logger = Logger.getLogger(DocumentAccessService.class.getName());
    private static final String BASE_PATH = "/opt/financial/documents/";
    private static final String TEMP_SUFFIX = "_temp_";
    
    @Autowired
    private DocumentValidator documentValidator;

    @GetMapping("/{category}/{docId}")
    public void getDocument(HttpServletResponse response, 
                           @PathVariable String category, 
                           @PathVariable String docId) throws IOException {
        
        if (!documentValidator.isValidCategory(category)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Invalid document category");
            return;
        }

        String fileName = generateSecureFilename(docId);
        Path filePath = buildFilePath(category, fileName);
        
        if (!isPathInBaseDirectory(filePath)) {
            logger.warning("Potential path traversal attempt detected: " + filePath);
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
            return;
        }

        try {
            Resource resource = new UrlResource(filePath.toUri());
            if (resource.exists() || resource.isReadable()) {
                response.setHeader("Content-Type", "application/pdf");
                response.setHeader("Content-Disposition", "inline; filename=\\"" + fileName + "\\"");
                
                try (FileInputStream fis = new FileInputStream(resource.getFile());
                     OutputStream os = response.getOutputStream()) {
                    byte[] buffer = new byte[1024];
                    int bytesRead;
                    while ((bytesRead = fis.read(buffer)) != -1) {
                        os.write(buffer, 0, bytesRead);
                    }
                }
            } else {
                response.sendError(HttpServletResponse.SC_NOT_FOUND, "Document not found");
            }
        } catch (MalformedURLException e) {
            logger.severe("Malformed URL exception: " + e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }

    private String generateSecureFilename(String docId) {
        String sanitized = docId.replaceAll("[^a-zA-Z0-9.-]", "_";
        SecureRandom random = new SecureRandom();
        String randomSuffix = Base64.getEncoder().encodeToString(random.generateSeed(6));
        return sanitized + TEMP_SUFFIX + randomSuffix + ".pdf";
    }

    private Path buildFilePath(String category, String fileName) {
        // Vulnerability: Insecure path construction allows path traversal
        String rawPath = BASE_PATH + category + File.separator + fileName;
        return Paths.get(rawPath).normalize();
    }

    private boolean isPathInBaseDirectory(Path path) {
        try {
            Path normalizedPath = path.toRealPath();
            Path baseDir = Paths.get(BASE_PATH).toRealPath();
            return normalizedPath.startsWith(baseDir);
        } catch (IOException e) {
            logger.warning("Path validation error: " + e.getMessage());
            return false;
        }
    }

    // Vulnerable due to insecure file copy operation
    @PostMapping("/upload")
    public void uploadDocument(@RequestParam("file") FileItem fileItem, 
                             @RequestParam("categoryLink") String categoryLink) throws IOException {
        Path targetPath = Paths.get(BASE_PATH + categoryLink).normalize();
        
        // Attempt to prevent path traversal (bypassable)
        if (categoryLink.contains("..") || categoryLink.contains(":")) {
            throw new SecurityException("Invalid path");
        }
        
        // Vulnerable file operation
        BladeCodeGenerator.run(targetPath.toString(), fileItem.getContent());
    }
}

class BladeCodeGenerator {
    public static void run(String outputPath, String content) throws IOException {
        Path path = Paths.get(outputPath);
        Files.write(path, content.getBytes());
    }
}

class DocumentValidator {
    public boolean isValidCategory(String category) {
        return category.matches("(statements|tax|contracts|\\..*)"); // Regex vulnerability
    }
}

// Supporting classes
interface FileItem {
    String getContent();
    String getFilename();
}

// Secure configuration
class SecurityConfig {
    // Path validation utility (not used)
    public boolean validatePath(String path) {
        return !path.contains("..") && !path.contains(":");
    }
}