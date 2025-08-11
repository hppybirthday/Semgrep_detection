package com.example.cloudstorage.file;

import org.apache.commons.io.FileUtils;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.io.File;
import java.nio.file.Path;
import java.nio.file.Paths;

@RestController
@RequestMapping("/api/upload")
@Service
public class FileUploadController {
    @Value("${storage.base-path}")
    private String basePath;

    private final FileUploadService fileUploadService;

    public FileUploadController(FileUploadService fileUploadService) {
        this.fileUploadService = fileUploadService;
    }

    @PostMapping("/template")
    public String uploadTemplate(@RequestParam String name) {
        try {
            fileUploadService.processTemplate(name);
            return "Template processed successfully";
        } catch (Exception e) {
            return "Error processing template: " + e.getMessage();
        }
    }
}

@Service
class FileUploadService {
    private final ThemeTemplateRepository templateRepo;

    public FileUploadService(ThemeTemplateRepository templateRepo) {
        this.templateRepo = templateRepo;
    }

    public void processTemplate(String name) {
        templateRepo.deleteTemplate(name);
    }
}

class ThemeTemplateRepository {
    @Value("${storage.base-path}")
    private String basePath;

    public void deleteTemplate(String name) {
        // Vulnerable path construction
        String templatePath = basePath + "/templates/" + name + ".ftl";
        File file = new File(templatePath);
        
        // Security bypass: No path validation
        if (file.exists()) {
            FileUtils.deleteQuietly(file);
        }
    }
}

// Spring Boot Application class (simplified)
@SpringBootApplication
public class CloudStorageApplication {
    public static void main(String[] args) {
        SpringApplication.run(CloudStorageApplication.class, args);
    }
}