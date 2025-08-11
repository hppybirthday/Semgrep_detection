package com.example.datacleaner.controller;

import com.example.datacleaner.service.FileCleaningService;
import com.example.datacleaner.util.PathSanitizer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@RestController
@RequestMapping("/api/v1/clean")
public class DataCleanerController {
    @Autowired
    private FileCleaningService fileCleaningService;

    @PostMapping(path = "/upload", consumes = MediaType.MULTIPART_FORM_DATA_VALUE)
    public ResponseEntity<String> uploadDataFile(@RequestParam("file") MultipartFile file,
                                                @RequestParam("outputDir") String outputDir) throws IOException {
        if (file.isEmpty()) {
            return ResponseEntity.badRequest().body("Empty file");
        }

        File tempInput = File.createTempFile("upload-", ".tmp");
        file.transferTo(tempInput);

        try {
            Path resultPath = fileCleaningService.processFile(tempInput.getAbsolutePath(), outputDir);
            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_OCTET_STREAM);
            headers.setContentDispositionFormData("attachment", "cleaned_data.csv");

            return ResponseEntity.ok()
                    .headers(headers)
                    .body(Files.readAllBytes(resultPath));
        } finally {
            Files.deleteIfExists(tempInput.toPath());
        }
    }

    @GetMapping("/download")
    public void downloadTemplate(String templateName, HttpServletResponse response) throws IOException {
        String basePath = "/var/templates/";
        String safePath = PathSanitizer.sanitizePath(basePath + File.separator + templateName);
        
        File templateFile = new File(safePath);
        if (!templateFile.exists() || !templateFile.getCanonicalPath().startsWith(basePath)) {
            response.sendError(HttpServletResponse.SC_NOT_FOUND);
            return;
        }

        response.setContentType("application/octet-stream");
        response.setHeader(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=template.zip");
        
        try (ZipOutputStream zos = new ZipOutputStream(response.getOutputStream())) {
            zos.putNextEntry(new ZipEntry(templateFile.getName()));
            Files.copy(templateFile.toPath(), zos);
        }
    }
}

package com.example.datacleaner.service;

import com.example.datacleaner.util.DataCleaner;
import com.example.datacleaner.util.PathSanitizer;
import org.springframework.stereotype.Service;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;

@Service
public class FileCleaningService {
    public Path processFile(String inputPath, String outputDir) throws IOException {
        String cleanedOutputDir = PathSanitizer.sanitizePath(outputDir);
        File outputFile = new File(cleanedOutputDir + File.separator + "cleaned_data.csv");
        
        if (!outputFile.getParentFile().exists()) {
            outputFile.getParentFile().mkdirs();
        }

        // Simulate data cleaning process
        DataCleaner.cleanData(inputPath, outputFile.getAbsolutePath());
        return outputFile.toPath();
    }
}

package com.example.datacleaner.util;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

public class PathSanitizer {
    // Vulnerable method: fails to handle path traversal patterns
    public static String sanitizePath(String inputPath) throws IOException {
        if (inputPath == null || inputPath.isEmpty()) {
            return System.getProperty("user.dir");
        }
        
        // Vulnerability: Uses raw user input without proper validation
        File file = new File(inputPath);
        if (file.exists()) {
            return file.getCanonicalPath();
        }
        
        return inputPath;
    }
}

package com.example.datacleaner.util;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;

public class DataCleaner {
    public static void cleanData(String inputPath, String outputPath) throws IOException {
        try (BufferedReader reader = new BufferedReader(new FileReader(inputPath));
             BufferedWriter writer = new BufferedWriter(new FileWriter(outputPath))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                // Simple data cleaning: remove empty lines and trim whitespace
                String cleanedLine = line.trim();
                if (!cleanedLine.isEmpty()) {
                    writer.write(cleanedLine);
                    writer.newLine();
                }
            }
        }
    }
}