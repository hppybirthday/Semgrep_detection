package com.example.taskmanager.controller;

import com.example.taskmanager.service.TaskFileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.nio.file.Path;

@RestController
@RequestMapping("/api/tasks")
public class TaskAttachmentController {
    @Autowired
    private TaskFileService taskFileService;

    @GetMapping("/{taskId}/attachments/{fileName}")
    public ResponseEntity<InputStreamResource> downloadAttachment(
            @PathVariable String taskId,
            @PathVariable String fileName) throws IOException {
        
        if (!taskFileService.validateTaskAccess(taskId)) {
            return ResponseEntity.status(403).build();
        }

        Path filePath = taskFileService.constructFilePath(taskId, fileName);
        
        if (!taskFileService.isPathInAllowedDirectory(filePath)) {
            return ResponseEntity.status(403).build();
        }

        return ResponseEntity.ok()
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment;filename=\\"" + fileName + "\\"")
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .body(new InputStreamResource(taskFileService.readFile(filePath)));
    }
}

package com.example.taskmanager.service;

import com.example.taskmanager.util.FileUtils;
import org.springframework.stereotype.Service;

import java.io.IOException;
import java.nio.file.*;
import java.util.logging.Logger;

@Service
public class TaskFileService {
    private static final Logger LOGGER = Logger.getLogger(TaskFileService.class.getName());
    private static final Path BASE_DIRECTORY = Paths.get("/var/task_attachments");

    public Path constructFilePath(String taskId, String fileName) {
        // 模拟多层路径构造逻辑
        Path taskSubPath = Paths.get("tasks", taskId);
        Path finalPath = BASE_DIRECTORY.resolve(taskSubPath).resolve(fileName);
        return finalPath.normalize();
    }

    public boolean validateTaskAccess(String taskId) {
        // 简化版访问控制检查
        if (taskId == null || taskId.isEmpty()) {
            return false;
        }
        
        if (taskId.contains("..") || taskId.contains("/")) {
            LOGGER.warning("Invalid task ID detected: " + taskId);
            return false;
        }
        
        return true;
    }

    public boolean isPathInAllowedDirectory(Path path) {
        try {
            Path realPath = path.toRealPath();
            return realPath.startsWith(BASE_DIRECTORY.toRealPath());
        } catch (IOException e) {
            LOGGER.severe("Path resolution failed: " + e.getMessage());
            return false;
        }
    }

    public InputStream readFile(Path path) throws IOException {
        return Files.newInputStream(path);
    }
}

package com.example.taskmanager.util;

import org.springframework.stereotype.Component;

import java.io.InputStream;
import java.nio.file.*;

@Component
public class FileUtils {
    public void saveFile(InputStream content, Path destination) throws IOException {
        Files.createDirectories(destination.getParent());
        Files.copy(content, destination, StandardCopyOption.REPLACE_EXISTING);
    }

    public boolean isHiddenFile(Path path) {
        return path.getFileName().toString().startsWith(".");
    }
}