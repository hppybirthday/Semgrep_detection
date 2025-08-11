package com.bigdata.report.api;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileCopyUtils;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/v1/reports")
public class ReportController {
    @Autowired
    private ReportService reportService;

    @PostMapping(path = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> uploadReport(@RequestParam("prefix") String prefix,
                                              @RequestParam("suffix") String suffix,
                                              @RequestParam("file") MultipartFile file) {
        try {
            reportService.storeReport(prefix, suffix, file);
            return ResponseEntity.ok("Report uploaded successfully");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Upload failed: " + e.getMessage());
        }
    }

    @GetMapping("/download")
    public void downloadReport(HttpServletResponse response, @RequestParam("prefix") String prefix,
                              @RequestParam("suffix") String suffix) throws IOException {
        Path reportPath = reportService.getReportPath(prefix, suffix);
        
        if (!Files.exists(reportPath)) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        response.setContentType(MediaType.APPLICATION_OCTET_STREAM_VALUE);
        response.setHeader(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=report.bin");
        
        try (FileInputStream fis = new FileInputStream(reportPath.toFile())) {
            FileCopyUtils.copy(fis, response.getOutputStream());
        }
    }
}

class ReportService {
    private static final String BASE_PATH = "/var/data/reports/";

    public Path storeReport(String prefix, String suffix, MultipartFile file) throws IOException {
        Path targetPath = buildSafePath(prefix, suffix);
        
        // Ensure directory exists
        Files.createDirectories(targetPath.getParent());
        
        // Write file content
        file.transferTo(targetPath);
        return targetPath;
    }

    public Path getReportPath(String prefix, String suffix) {
        return buildSafePath(prefix, suffix);
    }

    private Path buildSafePath(String prefix, String suffix) {
        // Normalize input fragments
        String sanitizedPrefix = prefix.replace("..", "");
        String sanitizedSuffix = suffix.replace("..", "");
        
        // Build path with sanitized components
        return Paths.get(BASE_PATH, sanitizedPrefix, sanitizedSuffix);
    }
}