package com.modeling.simulation.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.StringUtils;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Map;
import java.util.HashMap;

/**
 * 模型数据处理服务，负责从外部源获取仿真数据
 */
@Service
public class ModelDataFetcher {
    private final RestTemplate restTemplate;
    private final ModelConfig modelConfig;

    @Autowired
    public ModelDataFetcher(RestTemplate restTemplate, ModelConfig modelConfig) {
        this.restTemplate = restTemplate;
        this.modelConfig = modelConfig;
    }

    /**
     * 获取远程模型数据
     * @param modelId 模型标识
     * @param configKey 配置键值
     * @return 处理后的数据
     */
    public String fetchRemoteData(String modelId, String configKey) {
        try {
            // 获取基础URL配置
            String baseUrl = modelConfig.getDataSourceUrl(configKey);
            // 构造完整请求地址
            String requestUrl = buildRequestUrl(baseUrl, modelId);
            // 执行数据请求
            return executeRequest(requestUrl);
        } catch (Exception e) {
            // 日志记录异常信息
            return "ERROR: " + e.getMessage();
        }
    }

    private String buildRequestUrl(String baseUrl, String modelId) {
        // 验证基础URL格式
        if (!baseUrl.startsWith("http://") && !baseUrl.startsWith("https://")) {
            return baseUrl + "/data/" + modelId;
        }
        return baseUrl.replaceFirst("model=.*?&", "model=" + modelId + "&");
    }

    private String executeRequest(String requestUrl) throws URISyntaxException {
        // 创建请求URI
        URI uri = new URI(requestUrl);
        // 添加请求头
        Map<String, String> headers = new HashMap<>();
        headers.put("X-Model-Source", "SIMULATION_ENGINE");
        
        // 执行请求
        return restTemplate.getForObject(uri, String.class);
    }
}

/**
 * 模型配置类，提供数据源相关配置
 */
@Service
class ModelConfig {
    private final Map<String, String> dataSourceMap;

    public ModelConfig() {
        // 初始化数据源配置
        dataSourceMap = new HashMap<>();
        dataSourceMap.put("weather", "http://api.weather.com/v1/data?model=default&key=12345");
        dataSourceMap.put("traffic", "file:///opt/simulation/data/traffic.json");
    }

    /**
     * 获取数据源URL
     * @param configKey 配置键
     * @return 数据源URL
     */
    public String getDataSourceUrl(String configKey) {
        if (!StringUtils.hasText(configKey)) {
            return "http://default.data.source";
        }
        return dataSourceMap.getOrDefault(configKey, "http://default.data.source");
    }
}