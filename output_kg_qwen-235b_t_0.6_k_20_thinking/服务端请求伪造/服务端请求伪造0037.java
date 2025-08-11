package com.example.ssrfdemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.web.reactive.function.client.WebClientFactory;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Component;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;

import java.util.logging.Logger;

@SpringBootApplication
public class SsrfDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }
}

@RestController
@RequestMapping("/api")
class ExternalResourceController {
    private static final Logger logger = Logger.getLogger(ExternalResourceController.class.getName());
    
    @Autowired
    private ResourceService resourceService;

    @GetMapping("/fetch")
    public Mono<String> fetchExternalResource(@RequestParam String url) {
        logger.info("Fetching external resource: " + url);
        return resourceService.fetchResource(url);
    }
}

@Service
class ResourceService {
    @Autowired
    private ExternalHttpClient externalHttpClient;

    public Mono<String> fetchResource(String url) {
        return externalHttpClient.makeRequest(url);
    }
}

@Component
class ExternalHttpClient {
    private final WebClient webClient;

    public ExternalHttpClient(WebClient.Builder builder) {
        this.webClient = builder.build();
    }

    public Mono<String> makeRequest(String url) {
        // Vulnerable: Directly using user-controlled URL without validation
        return webClient.get()
            .uri(url)
            .retrieve()
            .bodyToMono(String.class);
    }
}

// Infrastructure layer
@Configuration
class WebClientConfig {
    @Bean
    public WebClient.Builder webClientBuilder() {
        return WebClient.builder();
    }
}