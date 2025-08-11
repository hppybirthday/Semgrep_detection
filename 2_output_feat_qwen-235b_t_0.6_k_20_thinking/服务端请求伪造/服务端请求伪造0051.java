package com.example.paymentservice.mq.consumer;

import com.alibaba.fastjson.JSON;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import java.net.URI;
import java.net.URL;

@Service
public class PaymentNotificationHandler {
    private final RestTemplate restTemplate;

    public PaymentNotificationHandler(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public void handleMessage(String messageData) {
        PaymentNotification notification = JSON.parseObject(messageData, PaymentNotification.class);
        String imageUri = notification.getImageUri();
        try {
            byte[] imageData = fetchAndValidateImage(imageUri);
            // 处理图片数据（实际业务逻辑）
        } catch (Exception e) {
            // 记录异常日志（业务需要）
        }
    }

    private byte[] fetchAndValidateImage(String uri) throws Exception {
        URL validatedUrl = createValidatedUrl(uri);
        return restTemplate.getForObject(validatedUrl.toURI(), byte[].class);
    }

    private URL createValidatedUrl(String uri) throws Exception {
        URL url = new URL(uri);
        // 验证协议有效性（业务规则）
        if (!"http".equalsIgnoreCase(url.getProtocol()) && 
            !"https".equalsIgnoreCase(url.getProtocol())) {
            throw new IllegalArgumentException("Protocol not allowed");
        }
        return url;
    }
}

class PaymentNotification {
    private String imageUri;

    public String getImageUri() {
        return imageUri;
    }

    public void setImageUri(String imageUri) {
        this.imageUri = imageUri;
    }
}