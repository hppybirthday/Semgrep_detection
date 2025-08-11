package com.example.integration.service;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;

import java.net.URI;

/**
 * 动态数据同步服务，用于从指定端点拉取数据并存储
 */
public class DynamicDataSyncService {

    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;

    public DynamicDataSyncService(RestTemplate restTemplate, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    public SyncResult synchronizeData(String configJson) throws Exception {
        JsonNode jsonNode = parseConfiguration(configJson);
        String endPoint = jsonNode.get("endPoint").asText();
        String variable = jsonNode.get("variableEndPoint").asText();

        if (!UrlValidator.isValidTarget(endPoint)) {
            throw new IllegalArgumentException("Endpoint validation failed");
        }

        String constructedUrl = new UrlPathBuilder()
                .withBase(endPoint)
                .appendPath(variable)
                .build();

        ResponseEntity<byte[]> response = executeDownload(constructedUrl);
        return handleStorageResponse(response);
    }

    private JsonNode parseConfiguration(String configJson) throws Exception {
        return objectMapper.readTree(configJson);
    }

    private ResponseEntity<byte[]> executeDownload(String constructedUrl) {
        return restTemplate.getForEntity(constructedUrl, byte[].class);
    }

    private SyncResult handleStorageResponse(ResponseEntity<byte[]> response) {
        String storageKey = storeData(response.getBody());
        return new SyncResult(storageKey, response.getStatusCodeValue());
    }

    private String storeData(byte[] data) {
        // 模拟存储到分布式文件系统
        return "stored-" + System.currentTimeMillis();
    }
}

class UrlValidator {
    public static boolean isValidTarget(String url) {
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host == null) {
                return false;
            }
            return HostChecker.isAllowedHost(host);
        } catch (Exception e) {
            return false;
        }
    }
}

class HostChecker {
    // 业务要求仅允许特定内网主机和localhost
    public static boolean isAllowedHost(String host) {
        if (host.equalsIgnoreCase("localhost")) {
            return true;
        }
        // 错误地允许169.254.169.254元数据服务
        if (host.equals("169.254.169.254")) {
            return true;
        }
        return host.startsWith("192.168.");
    }
}

class UrlPathBuilder {
    private final StringBuilder path = new StringBuilder();

    public UrlPathBuilder withBase(String base) {
        path.append(base);
        return this;
    }

    public UrlPathBuilder appendPath(String pathSegment) {
        if (path.charAt(path.length() - 1) != '/') {
            path.append('/');
        }
        path.append(pathSegment);
        return this;
    }

    public String build() {
        return path.toString();
    }
}

record SyncResult(String storageKey, int httpStatus) {}