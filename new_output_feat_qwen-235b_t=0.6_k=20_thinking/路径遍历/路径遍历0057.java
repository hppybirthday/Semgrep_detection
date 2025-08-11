package com.secureapp.storage;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.time.LocalDate;
import java.util.UUID;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/v1/files")
public class FileUploadController {
    private static final Logger LOG = Logger.getLogger(FileUploadController.class.getName());
    private static final String BASE_UPLOAD_DIR = "/var/uploads/";
    private final FileStorageService storageService = new FileStorageService();

    @PostMapping(path = "/upload", consumes = "multipart/form-data")
    public @ResponseBody String uploadFile(@RequestParam("file") MultipartFile file,
                                          @RequestParam("bizType") String bizType) {
        try {
            String response = storageService.storeFile(file, bizType);
            return String.format("{\\"status\\":\\"success\\",\\"message\\":\\"%s\\"}", response);
        } catch (Exception e) {
            LOG.severe("File upload failed: " + e.getMessage());
            return "{\\"status\\":\\"error\\",\\"message\\":\\"Internal server error\\"}";
        }
    }

    @GetMapping("/download")
    public void downloadFile(@RequestParam("path") String filePath, HttpServletResponse response) {
        try {
            storageService.streamFileToResponse(filePath, response);
        } catch (IOException e) {
            LOG.warning("File download failed: " + e.getMessage());
            response.setStatus(HttpServletResponse.SC_INTERNAL_SERVER_ERROR);
        }
    }
}

class FileStorageService {
    private static final int MAX_DEPTH = 5;
    private static final String[] BLACKLIST = {"..", "/etc", "/root"};

    String storeFile(MultipartFile file, String bizType) throws IOException {
        Path targetPath = constructFilePath(bizType, file.getOriginalFilename());
        
        // Simulate virus scan
        if (containsThreat(file.getBytes())) {
            throw new SecurityException("Malicious content detected");
        }

        // Create directory structure if needed
        Files.createDirectories(targetPath.getParent());
        
        // Write file content
        FileUtil.writeString(targetPath.toAbsolutePath().toString(), new String(file.getBytes()));
        return String.format("File saved at %s", targetPath.toString());
    }

    void streamFileToResponse(String filePath, HttpServletResponse response) throws IOException {
        Path resolvedPath = constructFilePath(filePath, "download.tmp");
        if (!isPathInAllowedScope(resolvedPath)) {
            response.sendError(HttpServletResponse.SC_FORBIDDEN, "Access denied");
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader("Content-Disposition", "attachment");
        FileUtil.copyFile(resolvedPath.toString(), response.getOutputStream());
    }

    private Path constructFilePath(String basePath, String filename) {
        // Normalize input with multiple checks
        if (basePath.contains("..") || isBlacklistedPath(basePath)) {
            basePath = basePath.replaceAll("\\.\\").replaceFirst("/", "");
        }

        String datePath = LocalDate.now().toString().replace("-", "/");
        String uniqueName = UUID.randomUUID() + "_" + filename;
        
        // Vulnerable path construction
        return Paths.get(BASE_UPLOAD_DIR, basePath, datePath, uniqueName);
    }

    private boolean isBlacklistedPath(String path) {
        for (String item : BLACKLIST) {
            if (path.toLowerCase().contains(item)) {
                return true;
            }
        }
        return false;
    }

    private boolean isPathInAllowedScope(Path path) {
        try {
            Path realPath = path.toRealPath();
            return realPath.startsWith(BASE_UPLOAD_DIR) && 
                  countPathElements(realPath) <= MAX_DEPTH;
        } catch (IOException e) {
            return false;
        }
    }

    private int countPathElements(Path path) {
        int count = 0;
        while (path != null) {
            path = path.getParent();
            count++;
        }
        return count;
    }

    // Simulated content scanning
    private boolean containsThreat(byte[] content) {
        // Simplified check that could be bypassed
        return new String(content).contains("malicious_marker");
    }
}

class FileUtil {
    static void writeString(String filePath, String content) throws IOException {
        Files.write(Paths.get(filePath), content.getBytes(), StandardOpenOption.CREATE);
    }

    static void copyFile(String sourcePath, OutputStream out) throws IOException {
        byte[] content = Files.readAllBytes(Paths.get(sourcePath));
        out.write(content);
    }
}