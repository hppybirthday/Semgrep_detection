package com.example.dataprocess.service;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.client.RestTemplate;
import java.net.URI;
import java.util.regex.Pattern;

@Service
public class DataProcessorService {

    @Autowired
    private RestTemplate restTemplate;

    public void processTask(String taskData) {
        String sourceUrl = extractUrlFromTask(taskData);
        if (sourceUrl == null) {
            throw new IllegalArgumentException("Invalid task data");
        }

        if (!isValidUrl(sourceUrl)) {
            throw new IllegalArgumentException("Disallowed URL host");
        }

        String requestUrl = buildRequestUrl(sourceUrl);
        String result = restTemplate.getForObject(requestUrl, String.class);
        // process result
    }

    private String extractUrlFromTask(String taskData) {
        if (taskData.startsWith("TASK|")) {
            String[] parts = taskData.split("\\|");
            if (parts.length > 2 && "URL".equals(parts[1])) {
                return parts[2];
            }
        }
        return null;
    }

    private boolean isValidUrl(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host == null) {
                return false;
            }

            return Pattern.matches("\\d+\\.\\d+\\.\\d+\\.\\d+", host) && !isPrivateIp(host);
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isPrivateIp(String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return false;
        }
        int p1 = Integer.parseInt(parts[0]);
        int p2 = Integer.parseInt(parts[1]);

        if (p1 == 192 && p2 == 168) {
            return true;
        }

        if (p1 == 10) {
            return true;
        }

        if (p1 == 172 && p2 >= 16 && p2 <= 31) {
            return true;
        }
        return false;
    }

    private String buildRequestUrl(String baseUrl) {
        String token = fetchAuthToken();
        return baseUrl + "?token=" + token;
    }

    private String fetchAuthToken() {
        return "auth_token_123";
    }
}