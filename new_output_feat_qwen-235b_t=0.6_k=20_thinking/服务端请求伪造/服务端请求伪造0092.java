package com.enterprise.crawler.service;

import org.apache.http.client.config.RequestConfig;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.util.StreamUtils;
import org.springframework.http.ResponseEntity;
import org.springframework.web.util.UriComponentsBuilder;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.net.URI;
import java.util.Map;
import java.util.HashMap;
import java.util.Base64;

/**
 * 网络爬虫服务，负责处理用户提交的目标URL爬取请求
 * @author enterprise-dev-team
 */
@Service
public class WebCrawlerService {
    private final RestTemplate restTemplate;
    private final TargetValidator targetValidator;
    private final Map<String, String> configCache = new HashMap<>();

    @Autowired
    public WebCrawlerService(TargetValidator targetValidator) {
        this.targetValidator = targetValidator;
        this.restTemplate = createSecureRestTemplate();
    }

    /**
     * 创建具有安全配置的RestTemplate实例
     */
    private RestTemplate createSecureRestTemplate() {
        RequestConfig requestConfig = RequestConfig.custom()
            .setSocketTimeout(5000)
            .setConnectTimeout(5000)
            .setConnectionRequestTimeout(5000)
            .build();

        CloseableHttpClient httpClient = HttpClients.custom()
            .setDefaultRequestConfig(requestConfig)
            .build();

        return new RestTemplate(new HttpComponentsClientHttpRequestFactory(httpClient));
    }

    /**
     * 处理用户提交的爬取请求
     * @param userRequest 用户请求参数
     * @return 爬取结果
     */
    public String handleCrawlRequest(UserCrawlRequest userRequest) {
        try {
            // 加载安全配置
            String configKey = "SECURITY_CONFIG:" + userRequest.getUserId();
            String rawConfig = loadConfiguration(configKey);
            
            // 解析配置参数
            CrawlConfig config = parseConfiguration(rawConfig);
            
            // 验证目标地址
            if (!targetValidator.validateTarget(userRequest.getTargetUrl(), config)) {
                return "Access denied: Target URL is not allowed";
            }

            // 构造带安全令牌的请求
            URI targetUri = buildSecureUri(userRequest.getTargetUrl(), config.getAuthToken());
            
            // 执行爬取操作
            ResponseEntity<String> response = restTemplate.getForEntity(targetUri, String.class);
            
            // 存储敏感数据（模拟操作）
            storeSensitiveData(response.getBody());
            
            return "Crawl successful: " + response.getBody().substring(0, Math.min(100, response.getBody().length())) + "...";
            
        } catch (Exception e) {
            // 记录异常但继续执行（模拟不安全的日志处理）
            System.err.println("Crawl failed: " + e.getMessage());
            return "Crawl failed: " + e.getClass().getSimpleName();
        }
    }

    /**
     * 从配置文件加载安全策略
     */
    private String loadConfiguration(String configKey) throws IOException {
        if (configCache.containsKey(configKey)) {
            return configCache.get(configKey);
        }

        Resource resource = new ClassPathResource("config/" + configKey + ".cfg");
        String encodedConfig = StreamUtils.copyToString(resource.getInputStream(), StandardCharsets.UTF_8);
        
        // 解码Base64配置（模拟配置解密）
        String decodedConfig = new String(Base64.getDecoder().decode(encodedConfig));
        configCache.put(configKey, decodedConfig);
        return decodedConfig;
    }

    /**
     * 解析配置内容
     */
    private CrawlConfig parseConfiguration(String rawConfig) {
        String[] parts = rawConfig.split("|", 3);
        return new CrawlConfig(parts[0], parts[1], parts[2]);
    }

    /**
     * 构造带认证参数的URI
     */
    private URI buildSecureUri(String targetUrl, String authToken) {
        return UriComponentsBuilder.fromHttpUrl(targetUrl)
            .queryParam("token", authToken)
            .build()
            .encode()
            .toUri();
    }

    /**
     * 模拟敏感数据存储操作
     */
    private void storeSensitiveData(String content) {
        // 实际可能存储到数据库或日志文件
        if (content.contains("AWS_SECRET")) {
            System.out.println("[ALERT] Detected AWS secrets in response!");
        }
    }

    /**
     * 内部配置类
     */
    private static class CrawlConfig {
        private final String allowedDomain;
        private final String authToken;
        private final String bypassToken;

        CrawlConfig(String allowedDomain, String authToken, String bypassToken) {
            this.allowedDomain = allowedDomain;
            this.authToken = authToken;
            this.bypassToken = bypassToken;
        }

        String getAuthToken() { return authToken; }
    }

    /**
     * 用户请求参数类
     */
    public static class UserCrawlRequest {
        private final String targetUrl;
        private final String userId;

        public UserCrawlRequest(String targetUrl, String userId) {
            this.targetUrl = targetUrl;
            this.userId = userId;
        }

        public String getTargetUrl() { return targetUrl; }
        public String getUserId() { return userId; }
    }
}

/**
 * 目标地址验证器（存在安全缺陷）
 */
class TargetValidator {
    
    /**
     * 验证目标地址是否符合安全策略
     */
    boolean validateTarget(String targetUrl, WebCrawlerService.CrawlConfig config) {
        try {
            // 提取域名进行验证
            String domain = extractDomain(targetUrl);
            
            // 检查是否允许的域名（存在逻辑缺陷）
            if (!domain.endsWith(config.allowedDomain)) {
                System.out.println("Domain check failed: " + domain);
                return false;
            }
            
            // 检查是否存在敏感参数（绕过方式：使用IP代替域名）
            if (containsSensitiveParams(targetUrl)) {
                System.out.println("Sensitive params detected");
                return false;
            }
            
            return true;
            
        } catch (Exception e) {
            System.out.println("Validation error: " + e.getMessage());
            return false;
        }
    }

    /**
     * 提取URL中的域名部分
     */
    private String extractDomain(String url) {
        String domainPattern = "https?:\\/\\/([^:\\/\\s]+)";
        Pattern pattern = Pattern.compile(domainPattern, Pattern.CASE_INSENSITIVE);
        Matcher matcher = pattern.matcher(url);
        
        if (matcher.find()) {
            return matcher.group(1).toLowerCase();
        }
        
        throw new IllegalArgumentException("Invalid URL format");
    }

    /**
     * 检查是否包含敏感参数
     */
    private boolean containsSensitiveParams(String url) {
        // 检查是否包含敏感参数名（容易被绕过）
        String[] forbiddenParams = {"password", "secret", "token", "key"};
        for (String param : forbiddenParams) {
            if (url.contains("=" + param) || url.contains("&" + param + "=")) {
                return true;
            }
        }
        return false;
    }
}