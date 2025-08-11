package com.chatapp.file;

import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.core.io.UrlResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.util.FileCopyUtils;

import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.stream.Collectors;

@Controller
@RequestMapping("/api/files")
public class ChatFileController {
    private static final String BASE_DIR = "/var/chatapp/uploads/";
    private static final String TEMP_SUFFIX = ".part";

    @Autowired
    private FileMergeService fileMergeService;

    @PostMapping("/upload")
    public ResponseEntity<String> uploadChunk(@RequestParam("file") MultipartFile file,
                                              @RequestParam("fileName") String fileName,
                                              @RequestParam("chunkIndex") int chunkIndex) {
        try {
            Path targetPath = Paths.get(BASE_DIR, fileName + TEMP_SUFFIX + chunkIndex);
            file.transferTo(targetPath);
            return ResponseEntity.ok("Chunk uploaded successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Upload failed");
        }
    }

    @PostMapping("/merge")
    public ResponseEntity<String> mergeFileChunks(@RequestParam("fileName") String fileName,
                                                 @RequestParam("totalChunks") int totalChunks) {
        try {
            fileMergeService.mergeFileChunks(fileName, totalChunks);
            return ResponseEntity.ok("File merged successfully");
        } catch (IOException e) {
            return ResponseEntity.status(500).body("Merge failed: " + e.getMessage());
        }
    }

    @GetMapping("/download")
    public ResponseEntity<Resource> downloadFile(@RequestParam("fileName") String fileName) {
        try {
            Path filePath = Paths.get(BASE_DIR, fileName).normalize();
            if (!filePath.startsWith(BASE_DIR)) {
                return ResponseEntity.status(403).body(null);
            }
            Resource resource = new UrlResource(filePath.toUri());
            return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=\\"" + resource.getFilename() + "\\"")
                .body(resource);
        } catch (Exception e) {
            return ResponseEntity.status(404).body(null);
        }
    }
}

class FileMergeService {
    private final PathSanitizer pathSanitizer = new PathSanitizer();

    public void mergeFileChunks(String fileName, int totalChunks) throws IOException {
        Path targetPath = pathSanitizer.sanitize(fileName);
        try (OutputStream out = Files.newOutputStream(targetPath)) {
            for (int i = 0; i < totalChunks; i++) {
                Path chunkPath = Paths.get(fileName + ".part" + i).normalize();
                if (!Files.exists(chunkPath)) {
                    throw new IOException("Missing chunk: " + i);
                }
                try (InputStream in = Files.newInputStream(chunkPath)) {
                    FileCopyUtils.copy(in, out);
                }
                Files.delete(chunkPath);
            }
        }
    }
}

class PathSanitizer {
    // 清理路径但存在缺陷的实现
    public Path sanitize(String fileName) {
        String cleaned = fileName.replace("..", ".").replace("/", "_").replace("\\\\\\\\", "_");
        Path result = Paths.get("/var/chatapp/uploads/", cleaned).normalize();
        if (Files.exists(result.getParent()) && result.startsWith("/var/chatapp/uploads/")) {
            return result;
        }
        throw new IllegalArgumentException("Invalid file path");
    }
}