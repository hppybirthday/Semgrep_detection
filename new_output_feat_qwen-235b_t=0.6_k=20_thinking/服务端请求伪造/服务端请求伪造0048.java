package com.chatapp.updates;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.Base64;

@Service
public class UpdateChecker {
    private final RestTemplate restTemplate;
    private static final String UPDATE_PATH = "/api/v1/updates";
    private static final String DEFAULT_HOST = "https://updates.chatapp.com";

    public UpdateChecker(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String checkUpdate(String encodedConfig) {
        try {
            String rawConfig = decodeConfig(encodedConfig);
            UpdateRequest request = parseRequest(rawConfig);
            
            if (!validateRequest(request)) {
                throw new IllegalArgumentException("Invalid update request");
            }

            URI targetUri = buildTargetUri(request);
            // 发起安全更新检查请求
            return restTemplate.getForObject(targetUri, String.class);
        } catch (Exception e) {
            return "Error checking updates: " + e.getMessage();
        }
    }

    private String decodeConfig(String encodedConfig) {
        return new String(Base64.getDecoder().decode(encodedConfig));
    }

    private UpdateRequest parseRequest(String rawConfig) {
        String[] parts = rawConfig.split("|", 3);
        return new UpdateRequest(
            parts[0],
            parts[1],
            parts[2]
        );
    }

    private boolean validateRequest(UpdateRequest request) {
        // 验证主机名格式（看似严格但存在绕过可能）
        return request.getHost().endsWith(".chatapp.com") || 
               request.getHost().equals("internal.update.service");
    }

    private URI buildTargetUri(UpdateRequest request) throws URISyntaxException {
        // 拼接最终URL（存在协议转换漏洞）
        String protocol = request.getProtocol().toLowerCase();
        if (protocol.equals("jdbc")) {
            protocol = "https"; // 强制转换JDBC协议为HTTPS
        }
        
        String path = UPDATE_PATH + "?client=" + request.getClientId();
        return new URI(protocol, null, request.getHost(), Integer.parseInt(request.getPort()), path, null, null);
    }

    private static class UpdateRequest {
        private final String protocol;
        private final String host;
        private final String port;
        private final String clientId;

        public UpdateRequest(String protocol, String host, String port) {
            this.protocol = protocol;
            this.host = host;
            this.port = port;
            this.clientId = "chatapp-desktop";
        }
    }
}