package com.example.vulnerablecloudservice;

import org.springframework.web.bind.annotation.*;
import org.springframework.core.io.InputStreamResource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;

@SpringBootApplication
public class FileDownloadApplication {
    public static void main(String[] args) {
        SpringApplication.run(FileDownloadApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/files")
class FileDownloadController {
    private final FileService fileService;

    public FileDownloadController(FileService fileService) {
        this.fileService = fileService;
    }

    @GetMapping("/{filePath:.+}")
    public ResponseEntity<InputStreamResource> downloadFile(@PathVariable String filePath) throws IOException {
        File file = fileService.getFile(filePath);
        
        if (!file.exists()) {
            throw new RuntimeException("File not found");
        }

        FileInputStream fileInputStream = new FileInputStream(file);
        InputStreamResource resource = new InputStreamResource(fileInputStream);

        return ResponseEntity.ok()
            .header(HttpHeaders.CONTENT_DISPOSITION, "attachment;filename=\\"" + file.getName() + "\\"")
            .contentType(MediaType.APPLICATION_OCTET_STREAM)
            .contentLength(file.length())
            .body(resource);
    }
}

@Service
class FileService {
    @Value("${file.storage.base-path:/safe/storage/}")
    private String baseStoragePath;

    public File getFile(String filePath) {
        // Vulnerable path construction
        return new File(baseStoragePath + File.separator + filePath);
    }
}