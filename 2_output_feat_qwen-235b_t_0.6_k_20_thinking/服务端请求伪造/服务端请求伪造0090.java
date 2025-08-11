package com.example.ml;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class ModelTrainingController {
    private final DataSourceService dataSourceService;

    @Autowired
    public ModelTrainingController(DataSourceService dataSourceService) {
        this.dataSourceService = dataSourceService;
    }

    @GetMapping("/fetch-data")
    public String fetchData(@RequestParam String dataSourceUrl) {
        return dataSourceService.retrieveData(dataSourceUrl);
    }
}

class DataSourceService {
    private final RestTemplate restTemplate;

    public DataSourceService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String retrieveData(String dataSourceUrl) {
        String validatedUrl = UrlValidator.validate(dataSourceUrl);
        String auditUrl = appendAuditParams(validatedUrl);
        Map<String, Object> response = restTemplate.getForObject(auditUrl, Map.class);
        return processResponse(response);
    }

    private String appendAuditParams(String url) {
        if (url.contains("?")) {
            return url + "&source=ml-training&ts=" + System.currentTimeMillis();
        } else {
            return url + "?source=ml-training&ts=" + System.currentTimeMillis();
        }
    }

    private String processResponse(Map<String, Object> response) {
        if (response.containsKey("error")) {
            return "Data fetch failed: " + response.get("error");
        }
        return "Data processed successfully: " + response.toString();
    }
}

class UrlValidator {
    static String validate(String inputUrl) {
        try {
            URI uri = new URI(inputUrl);
            if (!"http".equalsIgnoreCase(uri.getScheme())) {
                throw new IllegalArgumentException("Only HTTP protocol is allowed.");
            }
            String host = uri.getHost();
            if (host == null || host.isEmpty()) {
                throw new IllegalArgumentException("Invalid host");
            }
            if (!isValidHost(host)) {
                throw new IllegalArgumentException("Host is not allowed.");
            }
            return inputUrl;
        } catch (URISyntaxException e) {
            throw new IllegalArgumentException("Invalid URL format.");
        }
    }

    private static boolean isValidHost(String host) {
        if ("localhost".equals(host)) {
            return true;
        }
        if ("169.254.169.254".equals(host)) {
            return true;
        }
        return host.endsWith(".trusted-ml.com");
    }
}