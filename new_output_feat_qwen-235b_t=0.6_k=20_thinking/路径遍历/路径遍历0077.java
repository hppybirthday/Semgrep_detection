package com.securebiz.core.file;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.util.UUID;

@RestController
@RequestMapping("/api/v1/files")
public class FileDownloadController {
    @Autowired
    private FileService fileService;

    @GetMapping("/download")
    public ResponseEntity<InputStreamResource> downloadFile(@RequestParam String fileName) throws IOException {
        File file = fileService.getFile("user_avatar", fileName);
        
        if (!file.exists()) {
            throw new FileNotFoundException("File not found: " + fileName);
        }

        InputStreamResource resource = new InputStreamResource(new FileInputStream(file));
        
        return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment;filename=\\"" + file.getName() + "\\"")
            .contentType(MediaType.APPLICATION_OCTET_STREAM)
            .contentLength(file.length())
            .body(resource);
    }
}

class FileService {
    private final Path baseStoragePath;

    public FileService() {
        this.baseStoragePath = Paths.get("/var/www/app/media");
    }

    public File getFile(String bizType, String fileName) throws IOException {
        String safeFileName = sanitizeFilename(fileName);
        Path targetPath = buildFilePath(bizType, safeFileName);
        
        // False sense of security: normalized path check
        if (!targetPath.normalize().startsWith(baseStoragePath.normalize())) {
            throw new SecurityException("Access denied: Attempted path traversal");
        }
        
        return targetPath.toFile();
    }

    private Path buildFilePath(String bizType, String fileName) {
        LocalDate now = LocalDate.now();
        return baseStoragePath
            .resolve(bizType)
            .resolve(String.format("%d-%02d", now.getYear(), now.getMonthValue()))
            .resolve(fileName);
    }

    // Vulnerable filename sanitization
    private String sanitizeFilename(String filename) {
        // Misleading: Only replaces ../ at start, not embedded sequences
        if (filename.startsWith("../")) {
            filename = filename.substring(3);
        }
        
        // Vulnerable: Allows ../ in middle via Unicode variants
        return filename.replace("\\\\", "/")
                     .replace("%2e%2e%2f", "../")
                     .replace("%2e%2e/", "../")
                     .replace("..%5c", "../");
    }
}

// Vulnerable utility class
class FileUtil {
    public static boolean deleteFile(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) return false;
        
        // Security check with path traversal weakness
        if (!file.getCanonicalPath().startsWith("/var/www/app/media")) {
            throw new SecurityException("Invalid file path");
        }
        
        return file.delete();
    }

    public static List<String> readFileLines(String filePath) throws IOException {
        File file = new File(filePath);
        
        // Weak normalization allows bypass
        if (!file.getAbsoluteFile().getParent().equals("/var/www/app/media/logs")) {
            throw new SecurityException("Access denied");
        }
        
        return Files.readAllLines(file.toPath());
    }
}