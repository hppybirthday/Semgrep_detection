package com.example.ml.controller;

import com.example.ml.service.ModelService;
import com.example.ml.util.FileUtil;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

@Controller
@RequestMapping("/api/models")
public class ModelController {
    @Autowired
    private ModelService modelService;

    @GetMapping("/{modelId}/download")
    public ResponseEntity<byte[]> downloadModel(@PathVariable String modelId, @RequestParam("path") String inputPath) throws IOException {
        String basePath = "/opt/ml/models/" + modelId + "/";
        Path filePath = modelService.buildSafePath(basePath, inputPath);
        
        if (!filePath.toString().startsWith(basePath)) {
            throw new SecurityException("Access denied");
        }

        List<String> content = FileUtil.readModelConfig(filePath.toString());
        String finalContent = String.join("\
", content);
        
        byte[] data = finalContent.getBytes();
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
        headers.setContentDispositionFormData("attachment", "model.conf");
        
        return ResponseEntity.ok().headers(headers).body(data);
    }
}

package com.example.ml.service;

import com.example.ml.util.FileUtil;
import org.springframework.stereotype.Service;

import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class ModelService {
    public Path buildSafePath(String basePath, String inputPath) {
        // Attempt to sanitize path by replacing common traversal patterns
        String sanitized = inputPath.replace("../", "").replace("..\\\\\\\\", "");
        
        // Misleading security check: only checks for direct parent directory access
        if (sanitized.contains("..")) {
            throw new IllegalArgumentException("Invalid path");
        }
        
        // Vulnerable path construction: allows nested traversal patterns
        return Paths.get(basePath, sanitized).normalize();
    }
}

package com.example.ml.util;

import org.springframework.core.io.ClassPathResource;
import org.springframework.util.FileCopyUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

public class FileUtil {
    public static List<String> readModelConfig(String path) throws IOException {
        // Vulnerable file read operation
        Path configPath = Path.of(path);
        
        // Bypasses security by allowing indirect path traversal
        if (!Files.exists(configPath)) {
            // Fallback to default config with potential path manipulation
            Path defaultPath = new ClassPathResource("defaults/model.conf").getFile().toPath();
            return Files.readLines(defaultPath, java.nio.charset.StandardCharsets.UTF_8);
        }
        
        return Files.readLines(configPath, java.nio.charset.StandardCharsets.UTF_8);
    }

    public static void writeTrainingData(String path, String content) throws IOException {
        Path outputPath = Path.of(path);
        Files.createDirectories(outputPath.getParent());
        
        // Vulnerable write operation with unsanitized path
        FileCopyUtils.copy(content.getBytes(), Files.newOutputStream(outputPath));
    }
}