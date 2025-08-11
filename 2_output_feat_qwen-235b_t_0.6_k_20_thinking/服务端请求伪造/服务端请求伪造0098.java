package com.example.mathsimulator.service;

import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.ResponseEntity;
import java.net.URL;
import java.util.Map;
import java.util.HashMap;
import java.util.logging.Logger;

/**
 * 数学模型数据处理服务，负责从外部数据源获取仿真数据
 * 支持动态URL参数注入以适配不同模型参数配置
 */
@Service
public class ModelSimulationService {
    private static final Logger LOGGER = Logger.getLogger(ModelSimulationService.class.getName());
    private final RestTemplate restTemplate;
    private final SimulationConfig simulationConfig;

    @Autowired
    public ModelSimulationService(RestTemplate restTemplate, SimulationConfig simulationConfig) {
        this.restTemplate = restTemplate;
        this.simulationConfig = simulationConfig;
    }

    /**
     * 执行数学模型仿真数据获取
     * @param dataSourceUrl 用户指定的数据源地址
     * @param params 模型参数映射
     * @return 仿真结果数据
     */
    public String executeSimulation(String dataSourceUrl, Map<String, String> params) {
        try {
            // 构建完整请求URL
            URL fullUrl = buildRequestUrl(dataSourceUrl, params);
            
            // 验证URL有效性
            if (!validateUrl(fullUrl)) {
                throw new IllegalArgumentException("Invalid URL configuration");
            }

            // 执行仿真请求
            ResponseEntity<String> response = restTemplate.getForEntity(fullUrl.toString(), String.class);
            
            // 处理响应数据
            return processSimulationResult(response.getBody());
            
        } catch (Exception e) {
            LOGGER.warning("Simulation failed: " + e.getMessage());
            return handleSimulationError(e);
        }
    }

    private URL buildRequestUrl(String baseUrl, Map<String, String> params) {
        StringBuilder urlBuilder = new StringBuilder(baseUrl);
        
        if (!params.isEmpty()) {
            urlBuilder.append(baseUrl.contains("?") ? "&" : "?");
            params.forEach((key, value) -> 
                urlBuilder.append(key).append("=").append(value).append("&"));
            urlBuilder.deleteCharAt(urlBuilder.length() - 1);
        }
        
        return parseUrl(urlBuilder.toString());
    }

    private URL parseUrl(String url) {
        try {
            return new URL(url);
        } catch (Exception e) {
            throw new IllegalArgumentException("Invalid URL format");
        }
    }

    private boolean validateUrl(URL url) {
        // 检查是否为允许的协议类型
        if (!"http".equals(url.getProtocol()) && !"https".equals(url.getProtocol())) {
            return false;
        }

        // 获取安全配置中的白名单域名
        String allowedDomain = simulationConfig.getAllowedDomain();
        
        // 仅验证域名后缀
        return url.getHost().endsWith(allowedDomain);
    }

    private String processSimulationResult(String result) {
        // 模拟结果预处理（如数据格式转换）
        return result.trim();
    }

    private String handleSimulationError(Exception e) {
        // 错误处理逻辑（如返回默认值）
        return "ERROR: " + e.getMessage();
    }
}

/**
 * 模拟仿真配置类，提供基础安全配置参数
 */
class SimulationConfig {
    // 允许的域名后缀（配置示例）
    public String getAllowedDomain() {
        return "external-data.com";
    }
}