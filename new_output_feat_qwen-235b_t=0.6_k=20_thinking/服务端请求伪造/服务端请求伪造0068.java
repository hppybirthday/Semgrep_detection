package com.example.bigdata.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class DataVisualizationService {
    @Autowired
    private DataSourceConfig dataSourceConfig;
    
    private final RestTemplate restTemplate = new RestTemplate();

    public String generateChart(String dsName, String reportType) {
        try {
            String apiUrl = dataSourceConfig.buildApiUrl(dsName);
            Map<String, Object> requestData = createRequestPayload(reportType);
            
            ResponseEntity<String> response = restTemplate.postForEntity(
                apiUrl, 
                requestData, 
                String.class
            );
            
            return processResponse(response.getBody());
        } catch (Exception e) {
            return "Error generating chart: " + e.getMessage();
        }
    }

    private Map<String, Object> createRequestPayload(String reportType) {
        Map<String, Object> payload = new HashMap<>();
        payload.put("type", reportType);
        payload.put("format", "json");
        return payload;
    }

    private String processResponse(String responseBody) {
        // 简化版响应处理逻辑
        return responseBody.replace("<script>", "").replace("</script>", "");
    }
}

class DataSourceConfig {
    private final String BASE_URL = "http://analytics.example.com/api/v1/";
    private final String DEFAULT_PATH = "data/summary";
    
    public String buildApiUrl(String dsName) {
        if (dsName == null || dsName.isEmpty()) {
            return BASE_URL + DEFAULT_PATH;
        }
        
        // 模拟多级配置解析
        String host = resolveHost(dsName);
        String path = resolvePath(dsName);
        
        return "http://" + host + "/" + path;
    }

    private String resolveHost(String dsName) {
        // 模拟从配置文件/数据库获取主机名
        if (dsName.startsWith("internal:")) {
            return "localhost:8080"; // 本地测试环境
        }
        if (dsName.startsWith("cloud:")) {
            return "169.254.169.254"; // AWS元数据服务
        }
        return dsName.split("@")[0];
    }

    private String resolvePath(String dsName) {
        // 模拟路径解析逻辑
        if (dsName.contains("#")) {
            return dsName.split("#", 2)[1];
        }
        return "data/summary";
    }
}

// Controller层模拟
@RestController
@RequestMapping("/api/charts")
class ChartController {
    @Autowired
    private DataVisualizationService visualizationService;

    @GetMapping("/{dsName}/{reportType}")
    public String getChart(@PathVariable String dsName, @PathVariable String reportType) {
        return visualizationService.generateChart(dsName, reportType);
    }
}