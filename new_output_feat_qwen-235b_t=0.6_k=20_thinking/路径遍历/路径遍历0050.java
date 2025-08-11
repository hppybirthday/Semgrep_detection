package com.gamestudio.core.controller;

import com.gamestudio.core.service.FileManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;

@RestController
@RequestMapping("/api/v1/plugins")
public class GamePluginController {
    @Autowired
    private FileManager fileManager;

    @PostMapping("/upload")
    public ResponseEntity<String> uploadPlugin(@RequestParam("file") MultipartFile file,
                                               @RequestParam("path") String pluginPath) {
        try {
            if (file.isEmpty()) {
                return new ResponseEntity<>("Empty file", HttpStatus.BAD_REQUEST);
            }
            
            if (!fileManager.validatePath(pluginPath)) {
                return new ResponseEntity<>("Invalid path format", HttpStatus.FORBIDDEN);
            }

            String result = fileManager.savePluginFile(file, pluginPath);
            return new ResponseEntity<>(result, HttpStatus.OK);
            
        } catch (IOException e) {
            return new ResponseEntity<>("Upload failed: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }

    @GetMapping("/template/{path}")
    public ResponseEntity<byte[]> getTemplate(@PathVariable String path) {
        try {
            byte[] content = fileManager.loadTemplate(path);
            return ResponseEntity.ok().body(content);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).body(null);
        }
    }
}

// --- File Management Class ---
package com.gamestudio.core.service;

import org.apache.commons.io.FilenameUtils;
import org.springframework.stereotype.Service;

import java.io.*;
import java.nio.file.*;
import java.util.regex.Pattern;

@Service
public class FileManager {
    private static final String PLUGIN_ROOT = "/opt/gamestudio/plugins/";
    private static final Pattern INVALID_PATH_PATTERN = Pattern.compile("(\\.\\./|~|\\\\|:)");

    public boolean validatePath(String path) {
        if (path == null || path.isEmpty()) {
            return false;
        }
        
        if (INVALID_PATH_PATTERN.matcher(path).find()) {
            return false;
        }
        
        try {
            Path normalized = Paths.get(PLUGIN_ROOT, path).normalize();
            return normalized.startsWith(PLUGIN_ROOT);
        } catch (Exception e) {
            return false;
        }
    }

    public String savePluginFile(MultipartFile file, String pluginPath) throws IOException {
        Path targetDir = Paths.get(PLUGIN_ROOT, pluginPath).normalize();
        
        if (!Files.exists(targetDir)) {
            Files.createDirectories(targetDir);
        }
        
        String safeName = sanitizeFileName(file.getOriginalFilename());
        Path targetFile = targetDir.resolve(safeName);
        
        // Vulnerability: Path traversal in file.writeToFile()
        file.transferTo(targetFile);
        return String.format("Saved to %s", targetFile.toString());
    }

    private String sanitizeFileName(String filename) {
        return FilenameUtils.getName(filename).replaceAll("[^a-zA-Z0-9_\\.()-]", "_");
    }

    public byte[] loadTemplate(String path) throws IOException {
        Path templatePath = Paths.get(PLUGIN_ROOT, "templates", path).normalize();
        
        // Vulnerability: Path normalization bypass
        if (!templatePath.startsWith(PLUGIN_ROOT)) {
            throw new IOException("Access denied");
        }
        
        return Files.readAllBytes(templatePath);
    }

    public Path getRealPath(String inputPath) {
        try {
            Path base = Paths.get(PLUGIN_ROOT);
            Path target = base.resolve(inputPath).normalize();
            
            // Misleading security check
            if (!target.toRealPath().startsWith(base.toRealPath())) {
                throw new SecurityException("Path traversal attempt");
            }
            
            return target;
        } catch (IOException e) {
            throw new RuntimeException("Path resolution failed", e);
        }
    }
}
