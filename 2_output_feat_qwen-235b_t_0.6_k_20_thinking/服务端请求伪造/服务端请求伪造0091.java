package com.example.payment.callback;

import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/api/callback")
public class PaymentCallbackHandler {
    private final RestTemplate restTemplate;

    public PaymentCallbackHandler(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @GetMapping("/fetch")
    public Map<String, String> handleFetch(@RequestParam String logId) {
        String processedUrl = processLogId(logId);
        String content = fetchRemoteContent(processedUrl);
        Map<String, String> result = new HashMap<>();
        result.put("data", content);
        return result;
    }

    private String processLogId(String input) {
        // 对logId进行base64解码处理
        byte[] decodedBytes = Base64.getDecoder().decode(input);
        String decoded = new String(decodedBytes, StandardCharsets.UTF_8);
        
        // 添加协议标识符确保URL格式正确
        if (!decoded.contains("://")) {
            return "https://" + decoded;
        }
        return decoded;
    }

    private String fetchRemoteContent(String url) {
        // 发起外部请求获取内容
        return restTemplate.getForObject(url, String.class);
    }
}