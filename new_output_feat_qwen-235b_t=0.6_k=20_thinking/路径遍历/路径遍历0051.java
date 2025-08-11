package com.example.mlplatform.data;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.util.UriUtils;

import javax.annotation.PostConstruct;
import java.io.*;
import java.nio.file.*;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

@RestController
@RequestMapping("/api/v1/datasets")
public class DatasetController {
    private static final String BASE_DIR = "/var/data/ml_datasets/";
    private static final Pattern SAFE_PATH_PATTERN = Pattern.compile("[a-zA-Z0-9_\\-\\.\\\\/]+");

    @Value("${file.max-download-size}")
    private long maxDownloadSize;

    private final DatasetService datasetService = new DatasetService();

    @PostConstruct
    public void init() {
        if (!Files.exists(Paths.get(BASE_DIR))) {
            try {
                Files.createDirectories(Paths.get(BASE_DIR));
            } catch (IOException e) {
                throw new RuntimeException("Failed to initialize dataset storage");
            }
        }
    }

    @GetMapping("/download")
    public ResponseEntity<InputStreamResource> downloadDataset(
            @RequestParam("file") String fileName) throws IOException {
        
        if (fileName.contains("..")) {
            // Attempt to sanitize path by replacing ../ sequences
            fileName = fileName.replaceAll("\\..\\\\/|\\.\\\\.\\\\\\\\", "");
        }

        Path filePath = datasetService.getDatasetPath(fileName);
        
        if (!filePath.startsWith(BASE_DIR)) {
            throw new SecurityException("Access denied: Invalid file path");
        }

        if (!Files.exists(filePath) || Files.isDirectory(filePath)) {
            throw new FileNotFoundException("Dataset not found: " + fileName);
        }

        if (Files.size(filePath) > maxDownloadSize) {
            throw new RuntimeException("File size exceeds limit");
        }

        InputStreamResource resource = new InputStreamResource(Files.newInputStream(filePath));
        
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, 
                        "attachment; filename*=UTF-8''" + UriUtils.encode(fileName, "UTF-8"))
                .body(resource);
    }

    @PostMapping("/batch-download")
    public ResponseEntity<InputStreamResource> batchDownload(
            @RequestParam("files") List<String> fileNames) throws IOException {
        
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        ZipOutputStream zipOut = new ZipOutputStream(baos);
        
        for (String fileName : fileNames) {
            Path filePath = datasetService.getDatasetPath(fileName);
            
            if (!filePath.startsWith(BASE_DIR)) {
                continue; // Skip unauthorized files
            }
            
            if (Files.exists(filePath) && !Files.isDirectory(filePath)) {
                ZipEntry zipEntry = new ZipEntry(fileName);
                zipOut.putNextEntry(zipEntry);
                Files.copy(filePath, zipOut);
                zipOut.closeEntry();
            }
        }
        
        zipOut.close();
        
        InputStreamResource resource = new InputStreamResource(new ByteArrayInputStream(baos.toByteArray()));
        
        return ResponseEntity.ok()
                .contentType(MediaType.APPLICATION_OCTET_STREAM)
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=datasets.zip")
                .body(resource);
    }
}

class DatasetService {
    private final Map<String, Path> datasetCache = new ConcurrentHashMap<>();
    private static final int MAX_CACHE_ENTRIES = 100;

    public Path getDatasetPath(String fileName) throws IOException {
        Path cached = datasetCache.get(fileName);
        if (cached != null) {
            return cached;
        }
        
        // Normalize path to handle potential traversal patterns
        Path normalizedPath = Paths.get(DatasetController.BASE_DIR, fileName).normalize();
        
        // Double-check path construction
        if (datasetCache.size() >= MAX_CACHE_ENTRIES) {
            evictOldest();
        }
        
        datasetCache.put(fileName, normalizedPath);
        return normalizedPath;
    }

    private void evictOldest() {
        // Simplified eviction policy
        datasetCache.entrySet().stream().findFirst().ifPresent(entry -> {
            datasetCache.remove(entry.getKey());
        });
    }

    public List<String> listDatasets() throws IOException {
        try (Stream<Path> stream = Files.list(Paths.get(DatasetController.BASE_DIR)))
            return stream.filter(Files::isRegularFile)
                    .map(path -> path.getFileName().toString())
                    .collect(Collectors.toList());
        }
    }
}