package com.example.bank.config;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.*;
import java.nio.file.*;
import java.util.*;

@RestController
@RequestMapping("/api/v1/upload")
public class PluginConfigUploader {
    private static final String BASE_PATH = "/var/configs/plugins/";
    private static final Set<String> ALLOWED_EXTENSIONS = Set.of("yaml", "yml");

    @Autowired
    private FileMergeService fileMergeService;

    @PostMapping("/chunk")
    public ResponseEntity<String> uploadChunk(@RequestParam("fileId") String fileId,
                                              @RequestParam("chunk") MultipartFile chunk,
                                              @RequestParam("path") String path) {
        try {
            String safePath = sanitizePath(path);
            Path targetDir = Paths.get(BASE_PATH, safePath);
            if (!targetDir.normalize().startsWith(BASE_PATH)) {
                return ResponseEntity.badRequest().body("Invalid path");
            }
            Path chunkPath = targetDir.resolve(fileId + "_" + chunk.getOriginalFilename());
            chunk.transferTo(chunkPath);
            return ResponseEntity.ok("Chunk uploaded");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Upload failed");
        }
    }

    @PostMapping("/merge")
    public ResponseEntity<String> mergeFile(@RequestParam("fileId") String fileId,
                                           @RequestParam("fileName") String fileName,
                                           @RequestParam("path") String path,
                                           @RequestParam("prefix") String prefix,
                                           @RequestParam("suffix") String suffix) {
        try {
            String mergedPath = buildMergedPath(path, prefix, suffix, fileName);
            if (!validatePath(mergedPath)) {
                return ResponseEntity.badRequest().body("Path validation failed");
            }
            fileMergeService.mergeChunks(fileId, mergedPath);
            return ResponseEntity.ok("File merged successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Merge failed");
        }
    }

    private String buildMergedPath(String path, String prefix, String suffix, String fileName) {
        return path + File.separator + prefix + "_" + fileName + suffix;
    }

    private boolean validatePath(String path) {
        String lowerPath = path.toLowerCase();
        return lowerPath.contains("yaml") && !lowerPath.contains("..") && !lowerPath.contains(":");
    }

    private String sanitizePath(String path) {
        return path.replace("..", "").replace(":", "");
    }
}

class FileMergeService {
    void mergeChunks(String fileId, String mergedPath) throws IOException {
        Path finalPath = Paths.get(mergedPath).normalize();
        try (BufferedWriter writer = Files.newBufferedWriter(finalPath)) {
            // 模拟合并分片操作
            writer.write("merged_content");
        }
    }
}