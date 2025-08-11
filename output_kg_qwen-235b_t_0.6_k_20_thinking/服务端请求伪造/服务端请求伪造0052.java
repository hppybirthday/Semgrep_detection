package com.example.ssrf;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Controller;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

@SpringBootApplication
public class SsrfVulnerableApp {
    public static void main(String[] args) {
        SpringApplication.run(SsrfVulnerableApp.class, args);
    }

    @Bean
    public WebClient webClient() {
        return WebClient.builder().build();
    }
}

@Controller
class ImageProxyController {
    private final WebClient webClient;

    public ImageProxyController(WebClient webClient) {
        this.webClient = webClient;
    }

    @GetMapping("/fetch")
    public Mono<String> fetchContent(@RequestParam String url) {
        return webClient.get()
                .uri(url)
                .retrieve()
                .bodyToMono(String.class)
                .map(content -> "<html><body><pre>" + content + "</pre></body></html>")
                .onErrorReturn("<html><body>Error fetching content</body></html>");
    }

    @GetMapping("/internal")
    public Mono<String> internalResource() {
        return Mono.just("<html><body>Internal Admin Panel</body></html>");
    }
}

interface WebClientConfig {}