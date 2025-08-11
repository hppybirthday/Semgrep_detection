package com.example.crawler;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.net.URI;

@SpringBootApplication
public class CrawlerApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrawlerApplication.class, args);
    }
}

@RestController
@RequestMapping("/joblog")
class CrawlerController {
    private final CrawlerService crawlerService;

    public CrawlerController(CrawlerService crawlerService) {
        this.crawlerService = crawlerService;
    }

    @GetMapping("/logDetailCat")
    public String fetchLogDetail(@RequestParam String url) {
        try {
            crawlerService.fetchExternalContent(url);
            return "Connection successful";
        } catch (IOException e) {
            return "Connection failed: " + e.getMessage();
        }
    }
}

@Service
class CrawlerService {
    private final CloseableHttpClient httpClient;

    public CrawlerService() {
        this.httpClient = HttpClients.createDefault();
    }

    public void fetchExternalContent(String permalink) throws IOException {
        URI uri = URI.create(permalink);
        HttpGet request = new HttpGet(uri);
        
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            client.execute(request);
        }
    }
}

@Configuration
class CrawlerConfig {
    // 实际生产环境可能包含更多安全配置
}