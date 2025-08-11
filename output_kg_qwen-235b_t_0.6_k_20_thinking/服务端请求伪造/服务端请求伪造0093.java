package com.example.ssrf.demo;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@SpringBootApplication
public class SsrfVulnerableApp {
    public static void main(String[] args) {
        SpringApplication.run(SsrfVulnerableApp.class, args);
    }

    @Bean
    public CloseableHttpClient httpClient() {
        return HttpClients.createDefault();
    }
}

@RestController
@RequestMapping("/api")
class ResourceController {
    private final CloseableHttpClient httpClient;

    public ResourceController(CloseableHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @GetMapping("/fetch")
    public String fetchResource(@RequestParam String url) {
        HttpGet request = new HttpGet(url);
        try (CloseableHttpResponse response = httpClient.execute(request)) {
            return EntityUtils.toString(response.getEntity(), "UTF-8");
        } catch (IOException e) {
            return "Error fetching resource: " + e.getMessage();
        } finally {
            request.releaseConnection();
        }
    }

    @GetMapping("/profile")
    public String getUserProfile(@RequestParam String username) {
        String safeUrl = "https://api.internal.service/users/" + username;
        HttpGet request = new HttpGet(safeUrl);
        try (CloseableHttpResponse response = httpClient.execute(request)) {
            return EntityUtils.toString(response.getEntity(), "UTF-8");
        } catch (IOException e) {
            return "Error fetching profile: " + e.getMessage();
        } finally {
            request.releaseConnection();
        }
    }
}
