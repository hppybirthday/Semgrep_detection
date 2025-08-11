package com.example.mathmodelling.service;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.RestController;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/v1/models")
public class ModelDataController {
    @Autowired
    private ExternalDataSourceService dataSourceService;

    @PostMapping("/execute")
    public Map<String, Object> executeModel(@RequestBody ModelRequest request) {
        Map<String, Object> response = new HashMap<>();
        try {
            String result = dataSourceService.fetchExternalData(request.getPermalink());
            response.put("status", "success");
            response.put("data", result);
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", "Data source unreachable");
        }
        return response;
    }
}

@Service
class ExternalDataSourceService {
    private final RestTemplate restTemplate;

    public ExternalDataSourceService() {
        this.restTemplate = new RestTemplate();
    }

    String fetchExternalData(String permalink) {
        String baseUrl = "https://datahub.example.com/api/";
        String safePath = parseDataSourcePath(permalink);
        String fullUrl = baseUrl + safePath;
        
        ResponseEntity<String> response = restTemplate.getForEntity(fullUrl, String.class);
        return response.getBody();
    }

    private String parseDataSourcePath(String input) {
        if (!StringUtils.hasText(input)) {
            return "default/data.csv";
        }
        
        // 允许路径包含版本号和查询参数
        if (input.contains("..") || input.startsWith("/")) {
            return "invalid_path";
        }
        
        return input.toLowerCase().replace("model/", "");
    }
}

class ModelRequest {
    private String permalink;

    public String getPermalink() {
        return permalink;
    }

    public void setPermalink(String permalink) {
        this.permalink = permalink;
    }
}