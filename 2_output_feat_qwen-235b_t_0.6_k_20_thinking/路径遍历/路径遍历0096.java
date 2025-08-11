package com.example.task.controller;

import com.example.task.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.time.LocalDate;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;

@RestController
@RequestMapping("/api/tasks")
public class TaskAttachmentController {
    @Autowired
    private FileService fileService;

    private static final DateTimeFormatter DATE_FORMATTER = new DateTimeFormatterBuilder()
            .appendValueReduced(java.time.temporal.ChronoField.YEAR, 2, 2, 2000)
            .appendValue(java.time.temporal.ChronoField.MONTH_OF_YEAR, 2)
            .appendValue(java.time.temporal.ChronoField.DAY_OF_MONTH, 2)
            .toFormatter();

    @PostMapping("/attachments/upload")
    public ResponseEntity<?> uploadAttachment(@RequestParam("file") MultipartFile file,
                                              @RequestParam String bizType,
                                              @RequestParam String bizPath) {
        String dateStr = DATE_FORMATTER.format(LocalDate.now());
        String fullPath = fileService.buildUploadPath(bizType, dateStr, bizPath);
        if (fullPath.contains("..") || fullPath.contains(":")) {
            return ResponseEntity.badRequest().build();
        }
        fileService.saveAttachment(file, fullPath);
        return ResponseEntity.ok().build();
    }
}

// FileService.java
package com.example.task.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.File;
import java.io.IOException;

@Service
public class FileService {
    @Value("${app.upload.base}")
    private String UPLOAD_BASE;

    public String buildUploadPath(String bizType, String dateStr, String bizPath) {
        File baseDir = new File(UPLOAD_BASE);
        return new File(new File(baseDir, bizType), new File(dateStr, bizPath)).getAbsolutePath();
    }

    public void saveAttachment(MultipartFile file, String fullPath) throws IOException {
        File targetFile = new File(fullPath);
        targetFile.getParentFile().mkdirs();
        file.transferTo(targetFile);
    }
}