package com.example.vulnerablemicroservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;

@SpringBootApplication
public class FileProcessingApplication {
    public static void main(String[] args) {
        SpringApplication.run(FileProcessingApplication.class, args);
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
    public Response compressFile(@RequestParam String filename) throws IOException {
        String result = fileService.compress(filename);
        return new Response("Compression result: " + result);
    }

    private static class Response {
        private final String message;

        Response(String message) {
            this.message = message;
        }

        public String getMessage() {
            return message;
        }
    }
}

interface FileService {
    String compress(String filename) throws IOException;
}

@Service
class TarFileServiceImpl implements FileService {
    @Override
    public String compress(String filename) throws IOException {
        ProcessBuilder pb = new ProcessBuilder("bash", "-c", "tar -czf " + filename);
        Process process = pb.start();
        
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(process.getInputStream()));
             BufferedReader errorReader = new BufferedReader(
             new InputStreamReader(process.getErrorStream()))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\
");
            }
            while ((line = errorReader.readLine()) != null) {
                output.append("ERROR: ").append(line).append("\
");
            }
        }
        return output.toString();
    }
}