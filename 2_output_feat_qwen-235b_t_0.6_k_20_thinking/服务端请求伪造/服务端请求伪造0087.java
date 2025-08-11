package com.example.iot.device;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URL;
import java.util.Arrays;

@Service
public class DeviceLogService {
    private final RestTemplate restTemplate;

    public DeviceLogService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String fetchDeviceLog(String logFileUrl) {
        try {
            URL url = parseUrl(logFileUrl);
            return downloadContent(url);
        } catch (Exception e) {
            return "Error: Invalid log source";
        }
    }

    private URL parseUrl(String urlString) throws Exception {
        URL url = new URL(urlString);
        if (!Arrays.asList("http", "https").contains(url.getProtocol().toLowerCase())) {
            throw new IllegalArgumentException("Only HTTP(S) protocols allowed");
        }
        return url;
    }

    private String downloadContent(URL url) {
        return restTemplate.getForObject(url.toString(), String.class);
    }
}