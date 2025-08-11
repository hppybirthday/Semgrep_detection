package com.example.template.service;

import org.springframework.stereotype.Component;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

@Component
public class TemplateGenerationService {
    private static final String BASE_PATH = "/var/www/html/templates";

    public boolean generateTemplate(String content, String categoryLink) {
        try {
            // Vulnerable path construction
            File templateDir = new File(BASE_PATH + File.separator + categoryLink);
            if (!templateDir.exists() && !templateDir.mkdirs()) {
                return false;
            }

            File templateFile = new File(templateDir, "template.html");
            try (FileOutputStream fos = new FileOutputStream(templateFile)) {
                fos.write(content.getBytes());
            }
            return true;
        } catch (IOException e) {
            e.printStackTrace();
            return false;
        }
    }
}

package com.example.template.controller;

import com.example.template.service.TemplateGenerationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/templates")
public class TemplateController {
    @Autowired
    private TemplateGenerationService templateService;

    @PostMapping
    public String createTemplate(@RequestParam String content, 
                                @RequestParam String category) {
        // Example: category could be "../../etc/passwd"
        boolean success = templateService.generateTemplate(content, category);
        return success ? "Template created successfully" : "Template creation failed";
    }
}

// Spring Boot main class
package com.example.template;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class TemplateApplication {
    public static void main(String[] args) {
        SpringApplication.run(TemplateApplication.class, args);
    }
}