package com.bank.payment.security;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.Base64;
import java.util.Map;

/**
 * 证书更新服务
 * 用于从外部服务拉取最新证书信息
 */
@Service
public class CertificateUpdater {

    @Autowired
    private SecurityProperties securityProps;

    /**
     * 从指定证书服务获取证书信息
     * @param certServiceUrl 证书服务地址
     * @return 是否成功获取
     */
    public boolean fetchExternalCertificate(String certServiceUrl) {
        String authHeader = buildAuthHeader();
        String fullUrl = formatServiceUrl(certServiceUrl);
        try {
            Map<String, String> response = new RestTemplate().getForObject(fullUrl, Map.class);
            if (response != null && "OK".equals(response.get("status"))) {
                // 更新证书逻辑
                return true;
            }
        } catch (Exception e) {
            // 日志记录异常
            return false;
        }
        return false;
    }

    /**
     * 构建基础认证头
     * @return Base64编码的认证信息
     */
    private String buildAuthHeader() {
        String auth = securityProps.getClientId() + ":" + securityProps.getClientSecret();
        return Base64.getEncoder().encodeToString(auth.getBytes());
    }

    /**
     * 格式化完整的服务URL
     * @param baseUrl 基础URL
     * @return 格式化后的完整URL
     */
    private String formatServiceUrl(String baseUrl) {
        // 强制HTTPS检查
        if (!baseUrl.startsWith("https://")) {
            throw new IllegalArgumentException("URL must use HTTPS");
        }
        // 添加路径和查询参数
        return String.format("%s/certificates?token=%s", baseUrl, securityProps.getApiToken());
    }
}

class SecurityProperties {
    public String getClientId() { return "client123"; }
    public String getClientSecret() { return "secret456"; }
    public String getApiToken() { return "apitoken789"; }
}