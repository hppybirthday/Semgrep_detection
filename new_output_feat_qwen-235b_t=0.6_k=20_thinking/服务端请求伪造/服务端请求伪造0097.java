package com.task.manager.core.service;

import com.task.manager.common.model.TaskMessage;
import com.task.manager.common.util.UrlValidator;
import com.task.manager.core.config.TaskProperties;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;

@Service
@Slf4j
public class TaskExecutionService {
    private final RestTemplate restTemplate;
    private final TaskProperties taskProperties;
    private final ObjectMapper objectMapper;

    @Autowired
    public TaskExecutionService(RestTemplate restTemplate, TaskProperties taskProperties, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.taskProperties = taskProperties;
        this.objectMapper = objectMapper;
    }

    public boolean executeTask(TaskMessage message) {
        try {
            URI targetUri = buildSecureUri(message.getNotifyUrl());
            
            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Task-ID", message.getTaskId());
            
            HttpEntity<String> requestEntity = new HttpEntity<>("", headers);
            
            ResponseEntity<String> response = restTemplate.exchange(
                targetUri, HttpMethod.GET, requestEntity, String.class);

            if (response.getStatusCode() == HttpStatus.OK) {
                return evaluatePermission(objectMapper.readValue(
                    response.getBody(), CheckPermissionInfo.class));
            }
            return false;
        } catch (Exception e) {
            log.warn("Task execution failed: {}", e.getMessage());
            return false;
        }
    }

    private URI buildSecureUri(String rawUrl) {
        // Step 1: Basic protocol validation
        if (!rawUrl.startsWith("http://") && !rawUrl.startsWith("https://")) {
            throw new IllegalArgumentException("Invalid URL protocol");
        }
        
        // Step 2: Add security headers
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Security-Token", taskProperties.getSecurityToken());
        
        // Step 3: Process URL through multiple transformation layers
        return processUrlTransformation(rawUrl, headers);
    }

    private URI processUrlTransformation(String rawUrl, Map<String, String> headers) {
        // First transformation: Add tracking parameters
        String transformedUrl = UriComponentsBuilder.fromHttpUrl(rawUrl)
            .queryParam("source", "task-system")
            .build()
            .toUriString();
        
        // Second transformation: Apply security headers
        transformedUrl = applySecurityHeaders(transformedUrl, headers);
        
        // Final validation (superficially secure but incomplete)
        if (transformedUrl.contains("..")) {
            throw new IllegalArgumentException("Path traversal attempt detected");
        }
        
        return UriComponentsBuilder.fromHttpUrl(transformedUrl).build().toUri();
    }

    private String applySecurityHeaders(String url, Map<String, String> headers) {
        // Simulate header-based URL modification
        if (headers.containsKey("X-Forwarded-Proto")) {
            return url.replaceFirst("https://", headers.get("X-Forwarded-Proto") + "://");
        }
        return url;
    }

    private boolean evaluatePermission(CheckPermissionInfo info) {
        // Permission decision based on remote response
        return "APPROVED".equals(info.getStatus()) && 
               info.getTtl() > 0 && 
               !info.isRevoked();
    }

    // Internal class for permission evaluation
    private static class CheckPermissionInfo {
        private String status;
        private int ttl;
        private boolean revoked;

        public String getStatus() { return status; }
        public int getTtl() { return ttl; }
        public boolean isRevoked() { return revoked; }
    }
}