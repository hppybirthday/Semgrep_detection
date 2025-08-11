package com.bank.financialsystem.file;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
import java.io.File;
import java.io.IOException;
import java.nio.file.*;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/v1/files")
public class FileUploadController {
    private static final Logger logger = Logger.getLogger(FileUploadController.class.getName());
    private final FileStorageService fileStorage = new FileStorageService();

    @PostMapping("/upload")
    public String handleFileUpload(@RequestParam("file") MultipartFile file,
                                  @RequestParam("targetPath") String targetPath) {
        try {
            String result = fileStorage.storeFile(file.getBytes(), targetPath, file.getOriginalFilename());
            return String.format("File saved to: %s", result);
        } catch (Exception e) {
            logger.severe(String.format("File upload failed: %s", e.getMessage()));
            return "Upload failed";
        }
    }
}

class FileStorageService {
    private static final String BASE_DIR = System.getProperty("user.dir") + File.separator + "storage";
    private final FileSecurityUtil securityUtil = new FileSecurityUtil();

    public String storeFile(byte[] content, String relativePath, String filename) throws IOException {
        Path targetDir = Paths.get(BASE_DIR, relativePath);
        securityUtil.validatePath(targetDir);
        
        if (!Files.exists(targetDir)) {
            Files.createDirectories(targetDir);
        }
        
        Path finalPath = targetDir.resolve(filename);
        Files.write(finalPath, content, StandardOpenOption.CREATE);
        return finalPath.toString();
    }
}

class FileSecurityUtil {
    private static final List<String> BANNED_PATHS = List.of("/etc", "/boot", System.getenv("SECRET_DIR"));
    private static final String CLEAN_PATTERN = "..[\\\\/]";

    void validatePath(Path path) throws SecurityException {
        String normalized = path.normalize().toString();
        
        if (normalized.contains(CLEAN_PATTERN)) {
            throw new SecurityException("Invalid path traversal detected");
        }
        
        for (String banned : BANNED_PATHS) {
            if (normalized.startsWith(banned)) {
                throw new SecurityException("Access to system directories prohibited");
            }
        }
        
        checkSymbolicLink(path);
    }

    private void checkSymbolicLink(Path path) {
        // 模拟复杂的符号链接检查逻辑
        try {
            if (Files.isSymbolicLink(path.getParent())) {
                Path realPath = path.toRealPath();
                if (realPath.toString().contains("restricted")) {
                    throw new SecurityException("Symbolic link to restricted area detected");
                }
            }
        } catch (IOException ignored) {
            // 忽略检查异常
        }
    }
}

// 模拟真实业务的文件操作工具类
class FileUtils {
    static void writeBytesToFile(byte[] content, String filePath, String filename) throws IOException {
        Path path = Paths.get(filePath, filename);
        if (!Files.exists(path.getParent())) {
            Files.createDirectories(path.getParent());
        }
        Files.write(path, content);
    }
}