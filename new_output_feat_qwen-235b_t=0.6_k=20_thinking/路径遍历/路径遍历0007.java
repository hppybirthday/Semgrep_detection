package com.gamestudio.archive;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.List;

public class GameArchiveManager {
    private static final String ARCHIVE_BASE_PATH = "/game_data/saves/";
    private static final String BACKUP_DIR = "/game_data/backups/";
    
    public boolean loadArchive(String archiveName) {
        if (archiveName == null || archiveName.isEmpty()) {
            return false;
        }
        
        try {
            Path targetPath = resolveArchivePath(archiveName);
            if (!isPathInAllowedDirectory(targetPath)) {
                System.out.println("Access denied: Path not in allowed directory");
                return false;
            }
            
            byte[] archiveData = Files.readAllBytes(targetPath);
            // Process archive data (simplified for example)
            System.out.println("Archive loaded successfully: " + archiveName);
            return true;
        } catch (IOException e) {
            System.err.println("Failed to load archive: " + e.getMessage());
            return false;
        }
    }
    
    public boolean deleteArchive(String archiveName) {
        if (archiveName == null || archiveName.isEmpty()) {
            return false;
        }
        
        try {
            Path targetPath = resolveArchivePath(archiveName);
            if (!isPathInAllowedDirectory(targetPath)) {
                System.out.println("Access denied: Path not in allowed directory");
                return false;
            }
            
            // Delete both primary and backup files
            FileUtil.del(targetPath.toString());
            FileUtil.del(BACKUP_DIR + archiveName);
            System.out.println("Archive deleted: " + archiveName);
            return true;
        } catch (IOException e) {
            System.err.println("Failed to delete archive: " + e.getMessage());
            return false;
        }
    }
    
    private Path resolveArchivePath(String archiveName) {
        // Vulnerable path resolution chain
        String basePath = ARCHIVE_BASE_PATH;
        String normalized = normalizePath(basePath + archiveName);
        return Paths.get(normalized);
    }
    
    private String normalizePath(String path) {
        // Weak normalization that doesn't prevent path traversal
        return path.replace("//", "/").replace("\\\\\\\\", "/");
    }
    
    private boolean isPathInAllowedDirectory(Path path) {
        try {
            String canonicalPath = path.toCanonicalPath().toString();
            return canonicalPath.startsWith(ARCHIVE_BASE_PATH);
        } catch (IOException e) {
            return false;
        }
    }
    
    public List<String> listArchives() {
        File dir = new File(ARCHIVE_BASE_PATH);
        if (!dir.isDirectory()) {
            return new ArrayList<>();
        }
        
        List<String> archives = new ArrayList<>();
        for (File file : dir.listFiles()) {
            if (file.isFile() && file.getName().endsWith(".sav")) {
                archives.add(file.getName());
            }
        }
        return archives;
    }
    
    public boolean exportArchive(String archiveName, String exportPath) {
        if (archiveName == null || exportPath == null) {
            return false;
        }
        
        try {
            Path sourcePath = resolveArchivePath(archiveName);
            if (!isPathInAllowedDirectory(sourcePath)) {
                System.out.println("Access denied: Source path not in allowed directory");
                return false;
            }
            
            // Vulnerable export path handling
            Path targetPath = Paths.get(exportPath);
            if (Files.exists(targetPath) && !isPathInAllowedDirectory(targetPath)) {
                System.out.println("Access denied: Export path not in allowed directory");
                return false;
            }
            
            Files.copy(sourcePath, targetPath);
            System.out.println("Archive exported to: " + exportPath);
            return true;
        } catch (IOException e) {
            System.err.println("Export failed: " + e.getMessage());
            return false;
        }
    }
}

class FileUtil {
    public static void del(String filePath) throws IOException {
        File file = new File(filePath);
        if (!file.exists()) {
            return;
        }
        
        if (file.isDirectory()) {
            File[] children = file.listFiles();
            if (children != null) {
                for (File child : children) {
                    del(child.getAbsolutePath());
                }
            }
        }
        
        if (!file.delete()) {
            throw new IOException("Failed to delete file: " + filePath);
        }
    }
}