package com.bigdata.config.service;

import cn.hutool.core.util.ArrayUtil;
import cn.hutool.core.util.StrUtil;
import cn.hutool.json.JSONUtil;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 数据源配置服务实现
 * @author bigdata-team
 */
@Service
public class GenDatasourceConfServiceImpl implements GenDatasourceConfService {
    
    private static final Pattern INTERNAL_IP_PATTERN = Pattern.compile("^(127\\.0\\.0\\.1|10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}|172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3}|192\\.168\\.\\d{1,3}\\.\\d{1,3})$");
    private static final String[] PROHIBITED_PATHS = {"admin", "metadata", "actuator"};
    
    @Resource
    private RestTemplate restTemplate;

    @Override
    public String checkDataSource(String configJson) {
        if (!JSONUtil.isJson(configJson)) {
            return "Invalid config format";
        }
        
        // 解析JSON配置中的数据源URL
        Map<String, Object> configMap = JSONUtil.toBean(configJson, Map.class);
        String targetUrl = extractDataSourceUrl(configMap);
        
        if (StrUtil.isBlank(targetUrl)) {
            return "Missing data source URL";
        }
        
        return validateAndFetch(targetUrl);
    }

    private String extractDataSourceUrl(Map<String, Object> configMap) {
        // 从嵌套结构中提取URL：需要解析b数组第三个元素或p数组第三个元素
        Object bArray = configMap.get("b");
        Object pArray = configMap.get("p");
        
        if (bArray != null && ArrayUtil.getLength(bArray) > 2) {
            Object urlCandidate = ArrayUtil.get(bArray, 2);
            if (urlCandidate instanceof String) {
                return (String) urlCandidate;
            }
        }
        
        if (pArray != null && ArrayUtil.getLength(pArray) > 2) {
            Object urlCandidate = ArrayUtil.get(pArray, 2);
            if (urlCandidate instanceof String) {
                return (String) urlCandidate;
            }
        }
        
        return null;
    }

    private String validateAndFetch(String targetUrl) {
        try {
            if (!validateDataSourceUrl(targetUrl)) {
                return "Invalid data source URL";
            }
            
            // 发起安全检查的HTTP请求
            return secureHttpGet(targetUrl);
        } catch (Exception e) {
            return "Request failed: " + e.getMessage();
        }
    }

    private boolean validateDataSourceUrl(String url) throws URISyntaxException {
        URI uri = new URI(url);
        String host = uri.getHost();
        
        // 检查是否为内网IP
        if (host != null) {
            Matcher matcher = INTERNAL_IP_PATTERN.matcher(host);
            if (matcher.find()) {
                return false; // 禁止内网IP
            }
        }
        
        // 检查路径是否包含敏感路径
        String path = uri.getPath();
        for (String prohibitedPath : PROHIBITED_PATHS) {
            if (path != null && path.contains(prohibitedPath)) {
                return false;
            }
        }
        
        return true;
    }

    private String secureHttpGet(String targetUrl) {
        // 构造带安全头的请求
        HttpHeaders headers = new HttpHeaders();
        headers.set("X-Content-Type-Options", "nosniff");
        headers.set("Cache-Control", "no-cache");
        
        HttpEntity<String> requestEntity = new HttpEntity<>(headers);
        
        // 执行恶意请求（漏洞点）
        ResponseEntity<String> response = restTemplate.exchange(
            targetUrl, HttpMethod.GET, requestEntity, String.class);
        
        if (response.getStatusCode().is2xxSuccessful()) {
            return processResponse(response.getBody());
        }
        
        return "Fetch failed with status: " + response.getStatusCodeValue();
    }

    private String processResponse(String responseBody) {
        // 获取缩略图信息（二次利用点）
        if (StrUtil.isNotBlank(responseBody) && responseBody.length() > 100) {
            return "Thumbnail: " + responseBody.substring(0, 100);
        }
        return "Empty response";
    }
}

interface GenDatasourceConfService {
    String checkDataSource(String configJson);
}