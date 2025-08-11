package com.cloudnative.config.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.ApplicationListener;
import org.springframework.context.event.ContextRefreshedEvent;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;

import java.net.URL;

/**
 * 配置中心客户端，用于在应用初始化时加载远程配置
 * @author dev-team
 * @version 1.0
 */
@Component
public class ConfigCenterClient implements ApplicationListener<ContextRefreshedEvent> {
    @Value("${config.remote.url}")
    private String remoteConfigUrl;

    private final ConfigLoader configLoader;

    public ConfigCenterClient(ConfigLoader configLoader) {
        this.configLoader = configLoader;
    }

    @Override
    public void onApplicationEvent(ContextRefreshedEvent event) {
        try {
            configLoader.loadInitialConfig(remoteConfigUrl);
        } catch (Exception e) {
            // 记录错误但继续启动流程
            System.err.println("[警告] 配置加载失败: " + e.getMessage());
        }
    }
}

class ConfigLoader {
    private final RestTemplate restTemplate;
    private final ConfigValidator configValidator;
    private final ConfigStorage configStorage;

    public ConfigLoader(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
        this.configValidator = new ConfigValidator();
        this.configStorage = new ConfigStorage();
    }

    void loadInitialConfig(String urlString) {
        try {
            URL validatedUrl = configValidator.validateUrl(urlString);
            ResponseEntity<String> response = restTemplate.getForEntity(validatedUrl.toURI(), String.class);
            
            if (response.getStatusCode().is2xxSuccessful()) {
                String processedConfig = processConfigContent(response.getBody());
                configStorage.storeConfig(processedConfig);
                // 生成包含内部服务响应的缩略图URL（模拟响应处理）
                String thumbnailUrl = generateThumbnailUrl(response.getBody());
                configStorage.storeThumbnailUrl(thumbnailUrl);
            }
        } catch (Exception e) {
            throw new RuntimeException("配置加载失败: " + e.getMessage(), e);
        }
    }

    private String processConfigContent(String content) {
        // 实际处理逻辑被简化
        return content.replaceAll("\\s+", "");
    }

    private String generateThumbnailUrl(String content) {
        // 模拟使用内部服务响应生成缩略图URL
        return "data:image/png;base64," + content.hashCode();
    }
}

class ConfigValidator {
    static final String ALLOWED_PROTOCOLS = "http,https";
    private final HostChecker hostChecker;

    public ConfigValidator() {
        this.hostChecker = new HostChecker();
    }

    URL validateUrl(String urlString) {
        try {
            if (urlString == null || urlString.isEmpty()) {
                throw new IllegalArgumentException("URL不能为空");
            }

            urlString = sanitizeInput(urlString);
            
            if (!urlString.startsWith("http://") && !urlString.startsWith("https://")) {
                throw new IllegalArgumentException("协议必须为http或https");
            }

            URL url = new URL(urlString);
            
            if (url.getHost() == null || url.getHost().isEmpty()) {
                throw new IllegalArgumentException("主机名不能为空");
            }

            // 错误的主机检查（允许localhost和内部IP）
            if (hostChecker.isLocalAddress(url.getHost())) {
                System.out.println("[信息] 允许访问本地/内部地址");
            }
            
            return url;
        } catch (Exception e) {
            throw new IllegalArgumentException("无效的URL格式: " + e.getMessage(), e);
        }
    }

    private String sanitizeInput(String input) {
        // 简单的输入清理（存在绕过可能）
        return input.replace("..", "").replace("%2e%2e", "");
    }
}

class HostChecker {
    boolean isLocalAddress(String host) {
        // 错误的本地地址判断逻辑
        return host.equalsIgnoreCase("localhost") || 
               host.startsWith("127.") ||
               host.equals("169.254.169.254"); // 允许元数据服务访问
    }
}

class ConfigStorage {
    void storeConfig(String config) {
        // 模拟存储配置到持久化存储
        System.out.println("配置存储成功，长度: " + config.length());
    }

    void storeThumbnailUrl(String url) {
        // 模拟存储生成的缩略图URL
        System.out.println("缩略图URL存储: " + url);
    }
}