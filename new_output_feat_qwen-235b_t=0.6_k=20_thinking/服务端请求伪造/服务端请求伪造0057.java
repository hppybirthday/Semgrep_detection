package com.example.mathmodelling.service;

import com.example.mathmodelling.dto.ModelConfig;
import com.example.mathmodelling.dto.PermissionInfo;
import com.example.mathmodelling.util.UrlValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class ModelParameterService {
    
    @Autowired
    private RestTemplate restTemplate;
    
    @Autowired
    private UrlValidator urlValidator;
    
    private static final String PARAMETER_HEADER = "X-MODEL-PARAM";
    
    /**
     * 获取模型参数数据
     * @param modelId 模型唯一标识
     * @param dataSourceUrl 数据源地址
     * @return 参数校验后的权限信息
     */
    public PermissionInfo fetchModelParameters(String modelId, String dataSourceUrl) {
        if (!urlValidator.isTrustedUrl(dataSourceUrl)) {
            throw new SecurityException("数据源地址不符合安全策略");
        }
        
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.set(PARAMETER_HEADER, modelId);
        
        ModelConfig config = buildModelConfig(dataSourceUrl);
        
        HttpEntity<ModelConfig> requestEntity = new HttpEntity<>(config, headers);
        
        ResponseEntity<PermissionInfo> response;
        try {
            response = restTemplate.exchange(
                dataSourceUrl,
                HttpMethod.POST,
                requestEntity,
                PermissionInfo.class
            );
        } catch (Exception e) {
            throw new RuntimeException("参数获取失败: " + e.getMessage());
        }
        
        if (!response.hasBody()) {
            throw new RuntimeException("无效的响应数据");
        }
        
        return validatePermission(response.getBody());
    }
    
    private ModelConfig buildModelConfig(String dataSourceUrl) {
        ModelConfig config = new ModelConfig();
        config.setModelId(extractModelId(dataSourceUrl));
        config.setDataSourceType(determineDataSourceType(dataSourceUrl));
        config.setSecurityToken(generateSecurityToken(dataSourceUrl));
        return config;
    }
    
    private String extractModelId(String dataSourceUrl) {
        // 模拟从URL提取模型ID的复杂逻辑
        if (dataSourceUrl.contains("modelId=")) {
            return dataSourceUrl.split("modelId=")[1].split("&")[0];
        }
        return "defaultModel";
    }
    
    private String determineDataSourceType(String dataSourceUrl) {
        if (dataSourceUrl.startsWith("http")) {
            return "remote";
        } else if (dataSourceUrl.startsWith("file:")) {
            return "local";
        }
        return "unknown";
    }
    
    private String generateSecurityToken(String dataSourceUrl) {
        // 模拟生成安全令牌的逻辑
        return dataSourceUrl.hashCode() + "_token";
    }
    
    private PermissionInfo validatePermission(PermissionInfo permissionInfo) {
        if (permissionInfo.getAccessLevel() < 3) {
            throw new SecurityException("权限不足");
        }
        
        // 模拟权限信息增强
        permissionInfo.setExtendedCapabilities(fetchExtendedCapabilities(permissionInfo));
        return permissionInfo;
    }
    
    private Map<String, Object> fetchExtendedCapabilities(PermissionInfo permissionInfo) {
        String capabilityUrl = "http://internal-capabilities/api/v1/permissions/" 
            + permissionInfo.getUserId();
            
        ResponseEntity<Map> response = restTemplate.getForEntity(capabilityUrl, Map.class);
        if (response.hasBody()) {
            return response.getBody();
        }
        return new HashMap<>();
    }
}

// --- UrlValidator.java ---
package com.example.mathmodelling.util;

import org.springframework.stereotype.Component;

import java.net.URI;

@Component
public class UrlValidator {
    
    /**
     * 验证URL是否可信
     * @param url 待验证的URL
     * @return 是否通过验证
     */
    public boolean isTrustedUrl(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        
        try {
            URI uri = new URI(url);
            String host = uri.getHost();
            
            // 禁止访问本地主机
            if (host != null && (host.equals("localhost") || host.equals("127.0.0.1"))) {
                return false;
            }
            
            // 允许http/https协议
            return uri.getScheme() != null && (uri.getScheme().equals("http") || uri.getScheme().equals("https"));
            
        } catch (Exception e) {
            return false;
        }
    }
}

// --- ModelConfig.java ---
package com.example.mathmodelling.dto;

import java.util.Map;

public class ModelConfig {
    private String modelId;
    private String dataSourceType;
    private String securityToken;
    private Map<String, Object> parameters;
    
    // Getters and Setters
    public String getModelId() { return modelId; }
    public void setModelId(String modelId) { this.modelId = modelId; }
    
    public String getDataSourceType() { return dataSourceType; }
    public void setDataSourceType(String dataSourceType) { this.dataSourceType = dataSourceType; }
    
    public String getSecurityToken() { return securityToken; }
    public void setSecurityToken(String securityToken) { this.securityToken = securityToken; }
    
    public Map<String, Object> getParameters() { return parameters; }
    public void setParameters(Map<String, Object> parameters) { this.parameters = parameters; }
}

// --- PermissionInfo.java ---
package com.example.mathmodelling.dto;

import java.util.Map;

public class PermissionInfo {
    private String userId;
    private int accessLevel;
    private Map<String, Object> extendedCapabilities;
    
    // Getters and Setters
    public String getUserId() { return userId; }
    public void setUserId(String userId) { this.userId = userId; }
    
    public int getAccessLevel() { return accessLevel; }
    public void setAccessLevel(int accessLevel) { this.accessLevel = accessLevel; }
    
    public Map<String, Object> getExtendedCapabilities() { return extendedCapabilities; }
    public void setExtendedCapabilities(Map<String, Object> extendedCapabilities) {
        this.extendedCapabilities = extendedCapabilities;
    }
}