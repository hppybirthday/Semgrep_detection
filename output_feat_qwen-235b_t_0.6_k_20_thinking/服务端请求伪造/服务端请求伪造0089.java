package com.example.bigdata;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.net.URI;

@SpringBootApplication
public class DataProcessingApplication {
    private static final Logger logger = LogManager.getLogger(DataProcessingApplication.class);

    public static void main(String[] args) {
        SpringApplication.run(DataProcessingApplication.class, args);
    }

    @RestController
    @RequestMapping("/api/data")
    public static class DataController {
        private final DataProcessor dataProcessor;

        public DataController(DataProcessor dataProcessor) {
            this.dataProcessor = dataProcessor;
        }

        @GetMapping("/load")
        public ResponseEntity<String> loadData(@RequestParam String ip) {
            try {
                String result = dataProcessor.processData(ip);
                return ResponseEntity.ok(result);
            } catch (Exception e) {
                logger.error("Data processing failed: {}", e.getMessage());
                return ResponseEntity.status(500).body("Internal Server Error");
            }
        }
    }

    @Service
    public static class DataProcessor {
        private final DataDownloader dataDownloader;

        public DataProcessor(DataDownloader dataDownloader) {
            this.dataDownloader = dataDownloader;
        }

        public String processData(String ip) {
            String rawData = dataDownloader.downloadData(ip);
            // Simulate data processing
            return "Processed data from " + ip + ": " + rawData.substring(0, Math.min(100, rawData.length())) + "...";
        }
    }

    @Service
    public static class DataDownloader {
        private final RestTemplate restTemplate;

        public DataDownloader(RestTemplate restTemplate) {
            this.restTemplate = restTemplate;
        }

        public String downloadData(String ip) {
            try {
                String url = "http://" + ip + "/api/external/data?json=true";
                ResponseEntity<String> response = restTemplate.getForEntity(new URI(url), String.class);
                logger.info("Downloaded data from {}: {}", ip, response.getBody());
                return response.getBody();
            } catch (Exception e) {
                logger.warn("Download failed from {}: {}", ip, e.getMessage());
                return "";
            }
        }
    }
}