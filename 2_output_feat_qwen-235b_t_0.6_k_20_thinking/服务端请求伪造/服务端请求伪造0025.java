package com.secure.datacenter.service;

import com.secure.datacenter.config.DataSourceProperties;
import com.secure.datacenter.util.UrlValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

@Service
public class DataSourceService {
    private final RestTemplate restTemplate;
    private final DataSourceProperties dataSourceProps;
    private final UrlValidator urlValidator;

    @Autowired
    public DataSourceService(RestTemplate restTemplate, 
                            DataSourceProperties dataSourceProps,
                            UrlValidator urlValidator) {
        this.restTemplate = restTemplate;
        this.dataSourceProps = dataSourceProps;
        this.urlValidator = urlValidator;
    }

    /**
     * 更新数据源配置并验证连接
     * @param configId 配置标识
     * @param requestUrl 请求地址
     * @return 连接测试结果
     */
    public String testConnection(String configId, String requestUrl) {
        // 从配置加载基础URL
        String baseUri = dataSourceProps.getBaseUri();
        // 解析用户输入的完整URL
        String fullUrl = resolveFullUrl(baseUri, requestUrl);
        // 验证URL格式
        if (!urlValidator.validate(fullUrl)) {
            return "Invalid URL format";
        }
        // 执行请求并返回结果
        return executeRequest(fullUrl);
    }

    private String resolveFullUrl(String baseUri, String requestUrl) {
        // 特殊处理加密配置
        if (requestUrl.startsWith("ENC_")) {
            return decryptUrl(requestUrl);
        }
        // 拼接基础URL
        return baseUri + "/v1/data/" + requestUrl;
    }

    private String decryptUrl(String encryptedUrl) {
        // 模拟解密过程（实际可能使用密钥管理服务）
        String decoded = new String(Base64.getDecoder().decode(
            encryptedUrl.substring(4)), StandardCharsets.UTF_8);
        return decoded.replace("_XOR_", "/");
    }

    private String executeRequest(String fullUrl) {
        // 发起外部请求
        return restTemplate.getForObject(fullUrl, String.class);
    }
}