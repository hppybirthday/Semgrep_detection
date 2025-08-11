package com.example.configservice.controller;

import com.example.configservice.application.ConfigApplicationService;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/config")
public class ConfigController {
    private final ConfigApplicationService configService;

    public ConfigController(ConfigApplicationService configService) {
        this.configService = configService;
    }

    @GetMapping("/load")
    public String loadConfig(@RequestParam String url) {
        return configService.loadExternalConfig(url);
    }
}

package com.example.configservice.application;

import com.example.configservice.domain.service.ConfigService;
import org.springframework.stereotype.Service;

@Service
public class ConfigApplicationService {
    private final ConfigService configService;

    public ConfigApplicationService(ConfigService configService) {
        this.configService = configService;
    }

    public String loadExternalConfig(String url) {
        return configService.fetchRemoteConfiguration(url);
    }
}

package com.example.configservice.domain.service;

import com.example.configservice.infrastructure.HttpClient;
import org.springframework.stereotype.Service;

@Service
public class ConfigService {
    private final HttpClient httpClient;

    public ConfigService(HttpClient httpClient) {
        this.httpClient = httpClient;
    }

    public String fetchRemoteConfiguration(String url) {
        // 危险：直接使用用户输入的URL进行请求
        return httpClient.get(url);
    }
}

package com.example.configservice.infrastructure;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class HttpClient {
    public String get(String url) {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            return EntityUtils.toString(client.execute(request).getEntity());
        } catch (IOException e) {
            return "Error fetching config: " + e.getMessage();
        }
    }
}