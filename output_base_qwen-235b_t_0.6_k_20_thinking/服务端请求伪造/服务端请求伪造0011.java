package com.bank.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;

@SpringBootApplication
public class CreditScoreService {
    
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
    
    @RestController
    @RequestMapping("/api/v1")
    public class CreditController {
        
        @GetMapping("/credit-score")
        public String getCreditScore(@RequestParam String creditAgencyUrl) {
            try {
                // Vulnerable code: Directly using user input in URL without validation
                URL url = new URL(creditAgencyUrl);
                HttpURLConnection connection = (HttpURLConnection) url.openConnection();
                connection.setRequestMethod("GET");
                
                BufferedReader reader = new BufferedReader(
                    new InputStreamReader(connection.getInputStream()));
                StringBuilder response = new StringBuilder();
                String line;
                
                while ((line = reader.readLine()) != null) {
                    response.append(line);
                }
                reader.close();
                
                return response.toString();
                
            } catch (Exception e) {
                return "Error fetching credit score: " + e.getMessage();
            }
        }
    }
    
    // Additional classes to simulate real-world context
    public static class CreditReport {
        private String reportId;
        private String riskAssessment;
        private int score;
        
        // Getters and setters
    }
    
    public static class FraudDetection {
        public boolean isSuspicious(String report) {
            return report.contains("high risk");
        }
    }
    
    public static void main(String[] args) {
        SpringApplication.run(CreditScoreService.class, args);
    }
}