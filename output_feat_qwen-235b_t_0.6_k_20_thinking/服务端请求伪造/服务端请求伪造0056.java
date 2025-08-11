package com.example.ml;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

@SpringBootApplication
public class MlApplication {
    public static void main(String[] args) {
        SpringApplication.run(MlApplication.class, args);
    }
}

@RestController
@RequestMapping("/api")
class ModelController {
    private final AttachmentService attachmentService;

    public ModelController(AttachmentService attachmentService) {
        this.attachmentService = attachmentService;
    }

    @GetMapping("/process")
    public ResponseEntity<String> processImage(@RequestParam String imageUri) throws IOException {
        String result = attachmentService.uploadFromUrl(imageUri);
        return ResponseEntity.ok("Model processed with response: " + result);
    }
}

@Service
class AttachmentService {
    public String uploadFromUrl(String imageUri) throws IOException {
        StringBuilder response = new StringBuilder();
        URL url = new URL(imageUri);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        connection.setRequestMethod("GET");
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream())
        );
        
        String line;
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        
        return response.toString();
    }
}