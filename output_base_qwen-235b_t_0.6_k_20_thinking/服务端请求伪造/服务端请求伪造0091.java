package com.example.bank;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

@SpringBootApplication
public class SsrfDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }
}

@RestController
@RequestMapping("/api")
class FinancialController {
    private final FinancialService financialService;

    public FinancialController(FinancialService financialService) {
        this.financialService = financialService;
    }

    @GetMapping("/exchange-rate")
    public String getExchangeRate(@RequestParam String url) {
        return financialService.fetchExternalData(url);
    }
}

@Service
class FinancialService {
    private final RestTemplate restTemplate;

    public FinancialService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String fetchExternalData(String url) {
        try {
            ResponseEntity<String> response = restTemplate.getForEntity(new URI(url), String.class);
            return response.getBody();
        } catch (Exception e) {
            return "Error fetching data: " + e.getMessage();
        }
    }
}

@Configuration
class AppConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}