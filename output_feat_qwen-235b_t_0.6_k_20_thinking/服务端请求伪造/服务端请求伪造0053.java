package com.example.ssrf.demo;

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
public class SsrfDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }
}

@RestController
@RequestMapping("/api")
class UrlFetchController {
    private final UrlFetchService urlFetchService;

    public UrlFetchController() {
        this.urlFetchService = new UrlFetchService();
    }

    @GetMapping("/fetch")
    public ResponseEntity<String> getExternalResource(@RequestParam String requestUrl) {
        try {
            String response = urlFetchService.fetchUrlContent(requestUrl);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Error fetching URL: " + e.getMessage());
        }
    }
}

class UrlFetchService {
    public String fetchUrlContent(String requestUrl) throws IOException {
        StringBuilder response = new StringBuilder();
        URL url = new URL(requestUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        
        connection.setRequestMethod("GET");
        
        try (BufferedReader in = new BufferedReader(
                new InputStreamReader(connection.getInputStream()))) {
            String inputLine;
            while ((inputLine = in.readLine()) != null) {
                response.append(inputLine);
            }
        }
        
        return response.toString();
    }
}