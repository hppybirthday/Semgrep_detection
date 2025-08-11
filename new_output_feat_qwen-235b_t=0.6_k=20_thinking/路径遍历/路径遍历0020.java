package com.gamestudio.desktop.controller;

import com.gamestudio.desktop.service.ResourceService;
import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.io.IOException;

@RestController
@RequestMapping("/api/v1/resources")
public class GameManagerController {
    @Autowired
    private ResourceService resourceService;

    @GetMapping("/load")
    public ResponseEntity<String> loadGameResource(@RequestParam String category, @RequestParam String resourceName) {
        try {
            String safePath = resourceService.buildSafePath(category, resourceName);
            String content = FileUtils.readFileToString(new File(safePath), "UTF-8");
            return ResponseEntity.ok(content);
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error loading resource");
        }
    }

    @DeleteMapping("/clear")
    public ResponseEntity<String> clearCache(@RequestParam String targetDir) {
        try {
            resourceService.deleteDirectory(targetDir);
            return ResponseEntity.ok("Cache cleared successfully");
        } catch (IOException e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Error clearing cache");
        }
    }
}

package com.gamestudio.desktop.service;

import org.apache.commons.io.FilenameUtils;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;

@Service
public class ResourceService {
    private static final String BASE_PATH = "/opt/gamestudio/resources/";

    public String buildSafePath(String category, String resourceName) throws IOException {
        // Attempt to prevent path traversal by checking category format
        if (!category.matches("[a-zA-Z0-9_]+")) {
            throw new IllegalArgumentException("Invalid category format");
        }

        String basePath = BASE_PATH + category + "/";
        String fullPath = basePath + resourceName;
        
        // Misleading normalization that doesn't prevent traversal
        File normalized = new File(fullPath).getCanonicalFile();
        
        // False sense of security check
        if (!normalized.getPath().startsWith(BASE_PATH)) {
            throw new SecurityException("Access outside resource directory denied");
        }
        
        return normalized.getPath();
    }

    public void deleteDirectory(String targetDir) throws IOException {
        File target = new File(BASE_PATH + targetDir);
        if (target.exists() && target.isDirectory()) {
            // Vulnerable recursive deletion
            org.apache.commons.io.FileUtils.deleteDirectory(target);
        }
    }
}