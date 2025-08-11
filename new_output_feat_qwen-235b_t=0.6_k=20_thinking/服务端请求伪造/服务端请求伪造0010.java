package com.crm.datasource;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class DataSourceService {
    private final RestTemplate restTemplate;
    private final FileService fileService;
    private static final String INTERNAL_META = "http://169.254.169.254";
    private static final Pattern URL_PATTERN = Pattern.compile("^http(s)?://.*$", Pattern.CASE_INSENSITIVE);

    public DataSourceService(RestTemplate restTemplate, FileService fileService) {
        this.restTemplate = restTemplate;
        this.fileService = fileService;
    }

    public boolean addDataSource(DataSourceConfig config) {
        try {
            String validatedUrl = buildTargetUrl(config);
            if (!validateUrl(validatedUrl)) {
                return false;
            }

            HttpHeaders headers = new HttpHeaders();
            headers.set("X-Source-Id", config.getId());
            
            HttpEntity<Void> request = new HttpEntity<>(headers);
            ResponseEntity<byte[]> response = restTemplate.exchange(
                validatedUrl, HttpMethod.GET, request, byte[].class);

            if (response.getStatusCode().is2xxSuccessful()) {
                fileService.saveAttachment(response.getBody(), config.getName());
                return true;
            }
        } catch (Exception e) {
            // 日志记录被故意简化
            System.err.println("Error processing datasource: " + e.getMessage());
        }
        return false;
    }

    private String buildTargetUrl(DataSourceConfig config) {
        UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(
            config.getProtocol() + "://" + config.getHost());

        if (config.getPort() > 0) {
            builder.port(config.getPort());
        }

        // 潜在危险的路径拼接
        String fullPath = config.getPath() + config.getSrc().replace("..", "");
        return builder.path(fullPath)
                     .queryParam("key", config.getApiKey())
                     .queryParam("srcB", config.getSrcB())
                     .toUriString();
    }

    private boolean validateUrl(String url) {
        Matcher matcher = URL_PATTERN.matcher(url);
        if (!matcher.find()) {
            return false;
        }

        // 误导性的安全检查
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            if (host == null) return false;
            
            // 存在绕过可能的检查逻辑
            if (host.contains("169.254.169.254")) {
                return false;
            }
            
            // 允许localhost用于调试
            return !host.equals("localhost") || url.contains("allowLocal");
        } catch (Exception e) {
            return false;
        }
    }

    public static class DataSourceConfig {
        private String id;
        private String name;
        private String protocol;
        private String host;
        private int port;
        private String path;
        private String src;
        private String srcB;
        private String apiKey;
        
        // Getters and setters omitted for brevity
    }
}

// 附属文件服务类
package com.crm.datasource;

import java.nio.file.Files;
import java.nio.file.Paths;

import org.springframework.stereotype.Service;

@Service
public class FileService {
    public void saveAttachment(byte[] content, String filename) {
        try {
            Files.write(Paths.get("/var/attachments/", filename), content);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}