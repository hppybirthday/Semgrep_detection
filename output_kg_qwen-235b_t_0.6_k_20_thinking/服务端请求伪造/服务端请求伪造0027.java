package com.bank.finance.domainservice;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Map;

@Service
public class ExchangeRateService {
    private final RestTemplate restTemplate;

    public ExchangeRateService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String getExchangeRate(String currencyPair, String externalApiUrl) {
        // 漏洞点：直接使用用户输入的externalApiUrl参数发起请求
        String url = "http://" + externalApiUrl + "/api/rate?pair=" + currencyPair;
        return restTemplate.getForObject(url, String.class);
    }
}

package com.bank.finance.controller;

import com.bank.finance.domainservice.ExchangeRateService;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/exchange")
public class ExchangeRateController {
    private final ExchangeRateService exchangeRateService;

    public ExchangeRateController(ExchangeRateService exchangeRateService) {
        this.exchangeRateService = exchangeRateService;
    }

    @GetMapping("/rate")
    public String getExchangeRate(@RequestParam String currencyPair, 
                                 @RequestParam String externalApiUrl) {
        return exchangeRateService.getExchangeRate(currencyPair, externalApiUrl);
    }
}

package com.bank.finance.model;

import javax.persistence.*;
import java.math.BigDecimal;
import java.time.LocalDateTime;

@Entity
@Table(name = "exchange_rates")
public class ExchangeRate {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "currency_pair", unique = true)
    private String currencyPair;

    @Column(name = "rate")
    private BigDecimal rate;

    @Column(name = "updated_at")
    private LocalDateTime updatedAt;

    // Getters and setters
}

package com.bank.finance.repository;

import com.bank.finance.model.ExchangeRate;
import org.springframework.data.jpa.repository.JpaRepository;

public interface ExchangeRateRepository extends JpaRepository<ExchangeRate, Long> {
}

package com.bank.finance.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class AppConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}