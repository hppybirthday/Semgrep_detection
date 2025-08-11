package com.secureapp.storage.service;

import java.io.IOException;
import java.nio.file.*;
import java.util.logging.Logger;

public class FileMergeService {
    private static final Logger LOGGER = Logger.getLogger(FileMergeService.class.getName());
    private static final String STORAGE_ROOT = "/var/app_data/uploads";
    
    public boolean mergeFileChunks(String categoryId, String tempDir, String targetFilename) {
        try {
            Path baseDir = Paths.get(STORAGE_ROOT, categoryId);
            Path sanitizedPath = PathSanitizerUtil.sanitizePath(baseDir.toString());
            
            if (!PathSanitizerUtil.checkAndCreateDirectory(sanitizedPath.toString())) {
                return false;
            }
            
            Path tempPath = Paths.get(STORAGE_ROOT, tempDir);
            if (!Files.isDirectory(tempPath)) {
                return false;
            }
            
            Path targetPath = Paths.get(sanitizedPath.toString(), targetFilename);
            try (DirectoryStream<Path> stream = Files.newDirectoryStream(tempPath)) {
                for (Path chunk : stream) {
                    if (Files.isRegularFile(chunk)) {
                        Files.write(targetPath, Files.readAllBytes(chunk),
                                   StandardOpenOption.CREATE_APPEND);
                        Files.delete(chunk);
                    }
                }
            }
            
            Files.deleteIfExists(tempPath);
            LOGGER.info("File merge completed: " + targetPath);
            return true;
            
        } catch (IOException e) {
            LOGGER.severe("Merge error: " + e.getMessage());
            return false;
        }
    }
}

class PathSanitizerUtil {
    private static final String[] BLACKLIST = {"..", "/tmp"};
    
    public static boolean checkAndCreateDirectory(String path) throws IOException {
        Path dirPath = Paths.get(path);
        if (Files.exists(dirPath)) {
            return Files.isDirectory(dirPath);
        }
        
        for (String forbidden : BLACKLIST) {
            if (path.contains(forbidden)) {
                return false;
            }
        }
        
        Files.createDirectories(dirPath);
        return true;
    }
    
    public static String sanitizePath(String input) {
        String normalized = Paths.get(input).normalize().toString();
        if (normalized.startsWith(STORAGE_ROOT)) {
            return normalized;
        }
        return STORAGE_ROOT + normalized;
    }
}

// 漏洞触发示例：
// categoryId 参数传入 "../../etc/passwd" 时，
// 由于PathSanitizerUtil的sanitizePath方法在Linux环境下
// 对绝对路径的处理缺陷，可能导致路径逃逸
// 例如：
// Paths.get("/var/app_data/uploads", "../../etc/passwd")
// 会被normalize()解析为 "/etc/passwd"