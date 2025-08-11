package com.example.vulnerable.service;

import org.springframework.stereotype.Service;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;

@Service
public class FileService {
    public String getFileContent(String fileName) throws IOException {
        String basePath = "/var/www/html/files/";
        File file = new File(basePath + fileName);
        
        if (!file.exists()) {
            throw new IOException("File not found");
        }
        
        StringBuilder content = new StringBuilder();
        try (FileReader reader = new FileReader(file)) {
            int c;
            while ((c = reader.read()) != -1) {
                content.append((char) c);
            }
        }
        return content.toString();
    }
}

package com.example.vulnerable.controller;

import com.example.vulnerable.service.FileService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/files")
public class FileController {
    @Autowired
    private FileService fileService;

    @GetMapping("/{fileName}")
    public String downloadFile(@PathVariable String fileName) throws Exception {
        // Vulnerable: Directly using user input in file path
        return fileService.getFileContent(fileName);
    }
}

package com.example.vulnerable;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class VulnerableApplication {
    public static void main(String[] args) {
        SpringApplication.run(VulnerableApplication.class, args);
    }
}

// Domain Model
package com.example.vulnerable.model;

public class FileInfo {
    private String name;
    private long size;
    
    // Getters and setters
}

// Repository Interface
package com.example.vulnerable.repository;

import com.example.vulnerable.model.FileInfo;
import java.util.List;

public interface FileRepository {
    List<FileInfo> listFiles();
    byte[] readFile(String name);
}