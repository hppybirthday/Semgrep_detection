package com.example.vulnerablemicroservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@SpringBootApplication
public class FileProcessingService {
    public static void main(String[] args) {
        SpringApplication.run(FileProcessingService.class, args);
    }
}

@RestController
@RequestMapping("/api/files")
class FileController {
    private final FileService fileService;

    public FileController(FileService fileService) {
        this.fileService = fileService;
    }

    @PostMapping("/compress")
    public String compressFile(@RequestParam String filename) {
        return fileService.compressFile(filename);
    }
}

class FileService {
    private final FileRepository fileRepository;

    public FileService(FileRepository fileRepository) {
        this.fileRepository = fileRepository;
    }

    public String compressFile(String filename) {
        try {
            // Vulnerable command execution
            Process process = Runtime.getRuntime().exec(
                "tar -czf /archives/" + filename + ".tar.gz " + filename);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            int exitCode = process.waitFor();
            return "Compression completed with exit code " + exitCode + ":\
" + output;
        } catch (IOException | InterruptedException e) {
            return "Error during compression: " + e.getMessage();
        }
    }
}

class File {
    private String name;

    public File(String name) {
        this.name = name;
    }

    public String getName() {
        return name;
    }
}

class FileRepository {
    public void save(File file) {
        // Simulated database persistence
        System.out.println("Saved file: " + file.getName());
    }
}