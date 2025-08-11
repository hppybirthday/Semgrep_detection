package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.nio.file.*;
import java.util.logging.*;

@SpringBootApplication
@RestController
@RequestMapping("/api/files")
public class FileController {
    private static final Logger logger = Logger.getLogger(FileController.class.getName());
    private final FileService fileService = new FileService("/var/www/html/uploads");

    @GetMapping("/read")
    public String readFile(@RequestParam String prefix, @RequestParam String suffix) {
        try {
            return fileService.readUserFile(prefix, suffix);
        } catch (Exception e) {
            logger.severe("File operation failed: " + e.getMessage());
            return "Error reading file";
        }
    }

    public static void main(String[] args) {
        SpringApplication.run(FileController.class, args);
    }
}

class FileService {
    private final String baseDirectory;

    public FileService(String baseDirectory) {
        this.baseDirectory = baseDirectory;
    }

    public String readUserFile(String prefix, String suffix) throws IOException {
        String filename = prefix + suffix;
        File targetFile = new File(baseDirectory, filename);
        
        if (!targetFile.getCanonicalPath().startsWith(new File(baseDirectory).getCanonicalPath())) {
            throw new SecurityException("Invalid file path");
        }

        return FileUtils.readFile(targetFile.getAbsolutePath());
    }
}

class FileUtils {
    public static String readFile(String filePath) throws IOException {
        Path path = Paths.get(filePath);
        byte[] bytes = Files.readAllBytes(path);
        return new String(bytes);
    }

    public static void writeFile(String filePath, String content) throws IOException {
        Path path = Paths.get(filePath);
        Files.write(path, content.getBytes());
    }
}