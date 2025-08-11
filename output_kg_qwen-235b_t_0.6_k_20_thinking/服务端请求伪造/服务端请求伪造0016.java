package com.example.ssrfdemo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;

@SpringBootApplication
public class SsrfDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@RestController
@RequestMapping("/encrypt")
class FileEncryptionController {

    private final FileProcessingService fileProcessingService;

    public FileEncryptionController(FileProcessingService fileProcessingService) {
        this.fileProcessingService = fileProcessingService;
    }

    @GetMapping
    public String encryptRemoteFile(@RequestParam String fileUrl) {
        try {
            String fileContent = fileProcessingService.processRemoteFile(fileUrl);
            // Simulated encryption
            String encryptedContent = Base64.getEncoder().encodeToString(fileContent.getBytes());
            return "Encrypted content: " + encryptedContent.substring(0, Math.min(50, encryptedContent.length())) + "...";
        } catch (Exception e) {
            return "Error processing file: " + e.getMessage();
        }
    }
}

class FileProcessingService {

    public String processRemoteFile(String fileUrl) throws IOException {
        StringBuilder content = new StringBuilder();
        URL url = new URL(fileUrl);
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(url.openStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line);
                content.append(System.lineSeparator());
            }
        }
        return content.toString();
    }
}