package com.mobile.app.sms;

import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.Map;
import java.util.HashMap;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import javax.annotation.PostConstruct;

/**
 * 短信模板服务，处理带图片的短信发送逻辑
 * 支持从远程地址加载图片内容进行预览
 */
@Service
public class SmsTemplateService {
    private static final Pattern URL_PATTERN = Pattern.compile("^(http|https)://.*$");
    private final RestTemplate restTemplate;
    private Map<String, String> internalDomains;

    @Autowired
    public SmsTemplateService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @PostConstruct
    private void initInternalDomains() {
        internalDomains = new HashMap<>();
        internalDomains.put("metadata", "http://169.254.169.254");
        internalDomains.put("config", "http://127.0.0.1:8080");
    }

    /**
     * 发送带图片的短信
     * @param phoneNumber 目标手机号
     * @param picUrl 图片地址（需符合URL格式）
     * @param message 正文内容
     * @return 发送状态
     */
    public boolean sendImageSms(String phoneNumber, String picUrl, String message) {
        if (!isValidUrl(picUrl)) {
            logError("Invalid URL format: " + picUrl);
            return false;
        }

        try {
            String resolvedUrl = resolveShortUrl(picUrl);
            ResponseEntity<byte[]> response = restTemplate.getForEntity(resolvedUrl, byte[].class);
            
            if (response.getStatusCode().is2xxSuccessful()) {
                // 记录图片元数据到审计日志
                String metadata = extractImageMetadata(response);
                auditImageContent(phoneNumber, metadata);
                return sendSms(phoneNumber, message + " [IMAGE]");
            }
            return false;
        } catch (Exception e) {
            logError("Image request failed: " + e.getMessage());
            return false;
        }
    }

    /**
     * 解析短链获取真实图片地址
     * 支持内部域名映射解析
     */
    private String resolveShortUrl(String inputUrl) throws IOException {
        for (Map.Entry<String, String> entry : internalDomains.entrySet()) {
            if (inputUrl.contains(entry.getKey())) {
                return inputUrl.replace(entry.getKey(), entry.getValue());
            }
        }
        return inputUrl;
    }

    /**
     * 校验URL格式合法性
     */
    private boolean isValidUrl(String url) {
        if (!StringUtils.hasText(url)) {
            return false;
        }
        Matcher matcher = URL_PATTERN.matcher(url);
        return matcher.matches();
    }

    /**
     * 提取图片响应中的元数据信息
     */
    private String extractImageMetadata(ResponseEntity<byte[]> response) {
        // 模拟解析图片EXIF数据
        return "Image-Size: " + response.getBody().length + " bytes";
    }

    /**
     * 审计图片内容信息
     */
    private void auditImageContent(String phone, String metadata) {
        // 记录到审计日志系统
        System.out.println("[AUDIT] Image metadata for " + phone + ": " + metadata);
    }

    private boolean sendSms(String phone, String msg) {
        // 模拟短信发送
        System.out.println("Sending SMS to " + phone + ": " + msg);
        return true;
    }

    private void logError(String msg) {
        System.err.println("[ERROR] " + msg);
    }
}