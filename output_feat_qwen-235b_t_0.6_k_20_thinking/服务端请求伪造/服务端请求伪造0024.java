package com.example.ml;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;

@SpringBootApplication
public class ImageAnalysisApplication {

    public static void main(String[] args) {
        SpringApplication.run(ImageAnalysisApplication.class, args);
    }

    @RestController
    public class AnalysisController {
        private final ImageAnalysisService analysisService = new ImageAnalysisService();

        @PostMapping("/analyze-image")
        public ResponseEntity<String> analyzeImage(@RequestParam String imageUri) {
            try {
                String result = analysisService.processAndAnalyze(imageUri);
                return ResponseEntity.ok("Analysis result: " + result);
            } catch (Exception e) {
                return ResponseEntity.status(500).body("Error processing request: " + e.getMessage());
            }
        }
    }

    public static class ImageAnalysisService {
        private final ImageProcessingUtil imageProcessor = new ImageProcessingUtil();

        public String processAndAnalyze(String imageUri) throws Exception {
            // Simulate ML processing pipeline
            String processedData = imageProcessor.processImage(imageUri);
            // Actual ML analysis would happen here
            return "Processed data: " + processedData.substring(0, Math.min(100, processedData.length())) + "...";
        }
    }

    public static class ImageProcessingUtil {
        public String processImage(String imageUri) throws Exception {
            // Vulnerable code: Directly using user input to construct URL
            HttpClient client = HttpClient.newBuilder()
                .connectTimeout(Duration.ofSeconds(10))
                .build();

            // SSRF vulnerability: No validation of target host
            HttpRequest request = HttpRequest.newBuilder()
                .uri(URI.create(imageUri))
                .timeout(Duration.ofSeconds(20))
                .GET()
                .build();

            HttpResponse<String> response = client.send(request, HttpResponse.BodyHandlers.ofString());
            
            // Response contains sensitive internal data
            return response.body();
        }
    }
}