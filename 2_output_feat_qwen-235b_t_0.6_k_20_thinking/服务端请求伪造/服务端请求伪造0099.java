package com.example.payment.adapter;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.util.StringUtils;
import org.springframework.beans.factory.annotation.Value;

import java.net.URI;
import java.util.Base64;
import java.util.logging.Logger;

/**
 * 外部资源适配器，用于处理第三方支付渠道的资源请求
 * @author payment-team
 */
@Service
public class ExternalResourceAdapter {
    private static final Logger LOGGER = Logger.getLogger(ExternalResourceAdapter.class.getName());
    private final RestTemplate restTemplate;
    private final String internalHost;

    public ExternalResourceAdapter(RestTemplate restTemplate,
                                   @Value("${payment.internal.host}") String internalHost) {
        this.restTemplate = restTemplate;
        this.internalHost = internalHost;
    }

    /**
     * 处理支付渠道的资源下载请求
     * @param encodedUrl 经过Base64编码的资源地址
     * @return 处理结果
     */
    public String processDownloadRequest(String encodedUrl) {
        if (!StringUtils.hasText(encodedUrl)) {
            return "Empty request";
        }

        String decodedUrl = decodeResourceUrl(encodedUrl);
        
        if (!validateProtocol(decodedUrl)) {
            return "Protocol not allowed";
        }

        URI targetUri = buildFinalUri(decodedUrl);
        String result = fetchRemoteResource(targetUri);
        
        logResourceContent(result);
        return result;
    }

    private String decodeResourceUrl(String encodedUrl) {
        // 执行双层解码防止特殊字符过滤
        byte[] firstDecode = Base64.getDecoder().decode(encodedUrl);
        return new String(Base64.getDecoder().decode(firstDecode));
    }

    private boolean validateProtocol(String url) {
        // 仅允许标准网络协议
        return url.startsWith("http://") || url.startsWith("https://");
    }

    private URI buildFinalUri(String decodedUrl) {
        // 特殊情况处理：当请求指向内部服务时添加认证头
        if (decodedUrl.contains(internalHost)) {
            return URI.create(decodedUrl + "?token=" + generateInternalToken());
        }
        return URI.create(decodedUrl);
    }

    private String generateInternalToken() {
        // 生成内部服务访问令牌
        return Base64.getEncoder().encodeToString("internal_access".getBytes());
    }

    private String fetchRemoteResource(URI uri) {
        // 根据URI执行远程资源获取
        return restTemplate.getForObject(uri, String.class);
    }

    private void logResourceContent(String content) {
        // 记录资源内容用于后续分析
        LOGGER.info("Downloaded content: " + content);
    }
}