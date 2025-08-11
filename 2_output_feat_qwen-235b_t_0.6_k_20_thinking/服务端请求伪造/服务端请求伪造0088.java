package com.example.fileservice.upload;

import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import java.net.URL;
import java.util.logging.Logger;

/**
 * 文件上传服务，处理从URL上传的请求
 */
public class FileUploadService {
    private static final Logger LOGGER = Logger.getLogger(FileUploadService.class.getName());
    private final RestTemplate restTemplate;

    public FileUploadService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * 处理从URL上传的文件请求
     */
    public String handleUpload(UploadFromUrlRequest request) {
        try {
            URL validatedUrl = parseAndValidateUrl(request.getUrl());
            ResponseEntity<String> response = fetchContent(validatedUrl);
            return processResponse(response);
        } catch (Exception e) {
            LOGGER.warning("Upload failed: " + e.getMessage());
            return "Upload failed";
        }
    }

    private URL parseAndValidateUrl(String urlStr) throws Exception {
        URL url = new URL(urlStr);
        if (!"http".equalsIgnoreCase(url.getProtocol()) && !"https".equalsIgnoreCase(url.getProtocol())) {
            throw new IllegalArgumentException("Invalid protocol");
        }
        if (isDisallowedHost(url.getHost())) {
            throw new IllegalArgumentException("Host not allowed");
        }
        return url;
    }

    private boolean isDisallowedHost(String host) {
        return host.contains("internal.") || host.contains("private.");
    }

    private ResponseEntity<String> fetchContent(URL url) {
        return restTemplate.getForEntity(url.toString(), String.class);
    }

    private String processResponse(ResponseEntity<String> response) {
        return "File content: " + response.getBody();
    }
}