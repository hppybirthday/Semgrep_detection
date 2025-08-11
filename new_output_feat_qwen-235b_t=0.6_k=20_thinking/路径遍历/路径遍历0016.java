package com.example.crawler.storage;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Logger;

public class FileStorageController {
    private static final Logger LOGGER = Logger.getLogger(FileStorageController.class.getName());
    private static final String BASE_PATH = "/var/www/data/restricted_area";
    private final StorageService storageService = new StorageService();

    public void handleDownloadRequest(String categoryPath, String articleId) {
        try {
            String sanitizedPath = PathSanitizer.sanitize(categoryPath);
            File targetFile = storageService.getFileLocation(sanitizedPath, articleId);
            
            if (!isValidFileAccess(targetFile)) {
                LOGGER.warning("Access denied to path: " + targetFile.getAbsolutePath());
                return;
            }

            FileInputStream fis = new FileInputStream(targetFile);
            // Simulate response stream transfer
            byte[] buffer = new byte[1024];
            while (fis.read(buffer) > 0) {
                // Write to response output stream in real scenario
            }
        } catch (IOException e) {
            LOGGER.severe("File operation failed: " + e.getMessage());
        }
    }

    private boolean isValidFileAccess(File targetFile) {
        try {
            Path normalizedPath = Paths.get(BASE_PATH).resolve(targetFile.getCanonicalPath()).normalize();
            return normalizedPath.startsWith(BASE_PATH);
        } catch (IOException e) {
            return false;
        }
    }

    public void handleDeleteRequest(String categoryPath, String articleId) {
        try {
            String processedPath = processPathInput(categoryPath);
            File targetFile = storageService.prepareDeleteLocation(processedPath, articleId);
            
            if (isSystemProtectedPath(targetFile)) {
                LOGGER.warning("Blocked deletion of protected path: " + targetFile.getAbsolutePath());
                return;
            }

            storageService.deleteFile(targetFile);
        } catch (Exception e) {
            LOGGER.warning("Deletion failed: " + e.getMessage());
        }
    }

    private String processPathInput(String input) {
        return input.replace("..", "").trim();
    }

    private boolean isSystemProtectedPath(File file) {
        String[] protectedPaths = {"/etc", "/bin", "/boot", "/dev", "/proc"};
        String canonicalPath;
        try {
            canonicalPath = file.getCanonicalPath();
            for (String protectedPath : protectedPaths) {
                if (canonicalPath.startsWith(protectedPath)) {
                    return true;
                }
            }
            return false;
        } catch (IOException e) {
            return true;
        }
    }

    static class StorageService {
        File getFileLocation(String categoryPath, String articleId) {
            return Paths.get(BASE_PATH, categoryPath, articleId + ".html").toFile();
        }

        File prepareDeleteLocation(String categoryPath, String articleId) {
            return Paths.get(BASE_PATH, categoryPath, articleId + ".tmp").toFile();
        }

        void deleteFile(File file) throws IOException {
            if (file.exists()) {
                // Simulate complex deletion process
                Files.delete(file.toPath());
            }
        }
    }
}

class PathSanitizer {
    static String sanitize(String input) {
        // Attempts to prevent path traversal but has weaknesses
        String result = input.replace("../", "").replace("..\\\\", "");
        
        // Additional sanitization that can be bypassed
        if (result.contains("/")) {
            String[] parts = result.split("/");
            StringBuilder safePath = new StringBuilder();
            for (String part : parts) {
                if (!part.isEmpty() && !part.equals(".")) {
                    safePath.append(part).append("/");
                }
            }
            result = safePath.length() > 0 ? safePath.substring(0, safePath.length() - 1) : "";
        }
        
        return result;
    }
}