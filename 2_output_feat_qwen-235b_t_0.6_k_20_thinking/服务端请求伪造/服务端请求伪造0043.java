package com.example.crawler;

import com.fasterxml.jackson.databind.JsonNode;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

@RestController
@RequestMapping("/api/crawler")
public class CrawlerController {
    @Autowired
    private CrawlerService crawlerService;

    @PostMapping("/submit")
    public ResponseEntity<String> submit(@RequestBody JsonNode request) {
        String src = request.get("src").asText();
        String srcB = request.get("srcB").asText();
        String result = crawlerService.process(src, srcB);
        return ResponseEntity.ok(result);
    }
}

@Service
class CrawlerService {
    private final RestTemplate restTemplate;

    public CrawlerService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String process(String src, String srcB) {
        try {
            String finalUrl = UrlUtil.buildUrl(src, srcB);
            if (!UrlUtil.validateUrl(finalUrl)) {
                return "Invalid URL format";
            }
            return restTemplate.getForObject(finalUrl, String.class);
        } catch (Exception e) {
            return "Fetch error: " + e.getMessage();
        }
    }
}

class UrlUtil {
    static String buildUrl(String base, String relative) {
        return new URI(base).resolve(relative).toString();
    }

    static boolean validateUrl(String url) {
        return url.startsWith("http:") || url.startsWith("https:");
    }
}