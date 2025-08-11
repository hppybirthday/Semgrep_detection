package com.example.mathmodelling.file;

import org.springframework.stereotype.Service;
import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

@Service
public class ModelFileService {
    private static final String BASE_PATH = "/var/math_models/";
    
    public String readModelFile(String filename) throws IOException {
        File file = new File(BASE_PATH + filename);
        if (!file.exists()) {
            throw new IOException("File not found: " + filename);
        }
        
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        return content.toString();
    }
}

package com.example.mathmodelling.controller;

import com.example.mathmodelling.file.ModelFileService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/models")
public class ModelController {
    private final ModelFileService fileService;

    public ModelController(ModelFileService fileService) {
        this.fileService = fileService;
    }

    @GetMapping("/{filename}")
    public String getModelFile(@PathVariable String filename) {
        try {
            return fileService.readModelFile(filename);
        } catch (Exception e) {
            return "Error reading file: " + e.getMessage();
        }
    }
}

package com.example.mathmodelling;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class MathModellingApplication {
    public static void main(String[] args) {
        SpringApplication.run(MathModellingApplication.class, args);
    }
}