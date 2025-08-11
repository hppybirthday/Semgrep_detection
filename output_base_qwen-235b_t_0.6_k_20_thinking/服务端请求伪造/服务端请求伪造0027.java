package com.bank.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.bind.annotation.*;

import java.net.URI;

@SpringBootApplication
public class ExchangeRateApp {
    public static void main(String[] args) {
        SpringApplication.run(ExchangeRateApp.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@RestController
@RequestMapping("/api/rate")
class ExchangeRateController {
    private final ExchangeRateService exchangeRateService;

    public ExchangeRateController(ExchangeRateService service) {
        this.exchangeRateService = service;
    }

    @GetMapping("/convert")
    public String getRate(@RequestParam String url) {
        return exchangeRateService.getExchangeRate(url);
    }
}

@Service
class ExchangeRateService {
    private final RestTemplate restTemplate;

    public ExchangeRateService(RestTemplate template) {
        this.restTemplate = template;
    }

    public String getExchangeRate(String url) {
        try {
            return restTemplate.getForObject(new URI(url), String.class);
        } catch (Exception e) {
            return "Error fetching rate: " + e.getMessage();
        }
    }
}

// Domain model
record ExchangeRate(String base, String target, double rate) {}
