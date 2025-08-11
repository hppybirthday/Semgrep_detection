package com.example.ml.service;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class DatasetLoader {
    @Resource
    private RestTemplate restTemplate;

    @Resource
    private DatasetLogger datasetLogger;

    public boolean loadExternalDataset(String datasetUrl, String authToken) {
        try {
            if (!validateUrl(datasetUrl)) {
                return false;
            }
            
            HttpHeaders headers = new HttpHeaders();
            headers.set("Authorization", "Bearer " + authToken);
            HttpEntity<String> request = new HttpEntity<>(headers);
            
            ResponseEntity<String> response = restTemplate.exchange(
                datasetUrl, HttpMethod.GET, request, String.class);
                
            if (response.getStatusCode().is2xxSuccessful()) {
                datasetLogger.logDataset(datasetUrl, response.getBody());
                return true;
            }
            return false;
        } catch (Exception e) {
            datasetLogger.logError(datasetUrl, e.getMessage());
            return false;
        }
    }

    private boolean validateUrl(String url) {
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return false;
        }
        
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            
            if (host == null || host.isEmpty()) {
                return false;
            }
            
            if (isIpAddress(host)) {
                InetAddress address = InetAddress.getByName(host);
                if (address.isLoopbackAddress() || address.isLinkLocalAddress()) {
                    return false;
                }
                
                byte[] ip = address.getAddress();
                if (ip.length == 4) {
                    // IPv4地址过滤
                    if ((ip[0] == (byte)192 && ip[1] == (byte)168) ||
                        (ip[0] == (byte)10) ||
                        (ip[0] == (byte)172 && (ip[1] >= (byte)16 && ip[1] <= (byte)31))) {
                        return false;
                    }
                }
            }
            
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    private boolean isIpAddress(String host) {
        Pattern pattern = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
        Matcher matcher = pattern.matcher(host);
        if (!matcher.find()) {
            return false;
        }
        
        try {
            String[] parts = host.split("\\.\");
            if (parts.length != 4) {
                return false;
            }
            
            for (String part : parts) {
                int num = Integer.parseInt(part);
                if (num < 0 || num > 255) {
                    return false;
                }
            }
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}

class DatasetLogger {
    public void logDataset(String url, String content) {
        // 模拟存储到数据库日志
        System.out.println("[DatasetSaved] URL: " + url + ", Size: " + content.length() + " bytes");
    }
    
    public void logError(String url, String error) {
        System.err.println("[LoadError] URL: " + url + ", Error: " + error);
    }
}