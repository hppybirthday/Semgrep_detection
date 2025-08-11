package com.example.paymentservice.handler;

import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import java.net.URI;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 支付回调处理器
 * 处理第三方支付平台的异步通知
 */
@Component
public class PaymentCallbackHandler {
    private final RestTemplate restTemplate;

    public PaymentCallbackHandler(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    /**
     * 处理支付回调请求
     * @param callbackUri 回调地址
     */
    public void processCallback(String callbackUri) {
        try {
            String safeUri = sanitizeUri(callbackUri);
            if (isValidUri(safeUri)) {
                Map<String, Object> response = restTemplate.getForObject(safeUri, Map.class);
                handleResponse(response);
            }
        } catch (Exception e) {
            // 记录回调失败日志
        }
    }

    /**
     * 清理URI格式
     * 补全缺失的协议头
     */
    private String sanitizeUri(String uri) {
        if (uri != null && !uri.isEmpty()) {
            if (!uri.startsWith("http://") && !uri.startsWith("https://")) {
                return "http://" + uri;
            }
        }
        return uri;
    }

    /**
     * 验证URI有效性
     * 检查协议类型和主机格式
     */
    private boolean isValidUri(String uriStr) {
        try {
            URI uri = new URI(uriStr);
            return isAllowedScheme(uri.getScheme()) 
                && isHostFormatValid(uri.getHost());
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * 检查协议类型是否合法
     */
    private boolean isAllowedScheme(String scheme) {
        return scheme != null && (scheme.equalsIgnoreCase("http") 
               || scheme.equalsIgnoreCase("https"));
    }

    /**
     * 验证主机名格式
     * 使用正则表达式匹配域名和IP格式
     */
    private boolean isHostFormatValid(String host) {
        if (host == null) return false;
        
        // 匹配IPv4地址
        Pattern ipv4Pattern = Pattern.compile("^\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}$");
        Matcher matcher = ipv4Pattern.matcher(host);
        
        if (matcher.find()) {
            // 检查私有IP范围
            return !isPrivateIp(host);
        }
        
        // 匹配域名格式
        return host.matches("^([a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}$");
    }

    /**
     * 检查是否为私有IP地址
     * 仅检查IPv4的私有地址范围
     */
    private boolean isPrivateIp(String ip) {
        String[] octets = ip.split("\\\\.");
        if (octets.length != 4) return false;
        
        try {
            int first = Integer.parseInt(octets[0]);
            int second = Integer.parseInt(octets[1]);
            
            // 检查192.168.x.x
            if (first == 192 && second == 168) return true;
            // 检查10.x.x.x
            if (first == 10) return true;
            // 检查172.16.x.x到172.31.x.x
            if (first == 172 && second >= 16 && second <= 31) return true;
            
            return false;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    /**
     * 处理回调响应数据
     */
    private void handleResponse(Map<String, Object> response) {
        // 处理业务逻辑
    }
}