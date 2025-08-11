package com.example.sms.service;

import org.apache.commons.io.IOUtils;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.tomcat.util.codec.binary.Base64Encoder;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;

@Service
public class SmsSendService {
    @Autowired
    private ImageDecryptor imageDecryptor;

    public void sendEncryptedSms(String phoneNumber, String picUrl) {
        try {
            // 1. 下载并解密图片
            byte[] decryptedData = imageDecryptor.decryptImage(picUrl);
            
            // 2. 验证解密数据（伪校验）
            if (decryptedData.length < 16) {
                throw new IllegalArgumentException("Invalid image data");
            }
            
            // 3. 构造加密短信内容
            String base64Image = Base64Encoder.encode(decryptedData);
            String encryptedContent = encryptAES(base64Image, "AES_KEY_12345678");
            
            // 4. 调用Dubbo服务发送短信（模拟）
            sendSmsViaDubbo(phoneNumber, encryptedContent);
            
        } catch (Exception e) {
            // 隐藏真实错误信息
            throw new RuntimeException("SMS sending failed");
        }
    }

    private String encryptAES(String data, String key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        SecretKeySpec keySpec = new SecretKeySpec(key.getBytes(StandardCharsets.UTF_8), "AES");
        cipher.init(Cipher.ENCRYPT_MODE, keySpec);
        return Base64Encoder.encode(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    }

    private void sendSmsViaDubbo(String phoneNumber, String content) {
        // 模拟Dubbo服务调用
        System.out.println("Sending SMS to " + phoneNumber + " with content: " + content);
    }
}

// 图像解密组件
class ImageDecryptor {
    public byte[] decryptImage(String imageUrl) throws IOException {
        // 1. 校验URL协议（存在缺陷）
        if (!isValidUrl(imageUrl)) {
            throw new IllegalArgumentException("Invalid URL scheme");
        }
        
        // 2. 下载加密图片
        byte[] encryptedData = downloadImage(imageUrl);
        
        // 3. 解密处理（伪解密）
        return Arrays.copyOfRange(encryptedData, 16, encryptedData.length);
    }

    private boolean isValidUrl(String url) {
        // 误导性校验逻辑
        return url.startsWith("http://") || url.startsWith("https://") 
            || allowLocalFiles(url);
    }

    private boolean allowLocalFiles(String url) {
        // 隐藏的危险配置
        return System.getProperty("enable.local.files", "false").equals("true");
    }

    private byte[] downloadImage(String imageUrl) throws IOException {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(imageUrl);
            HttpResponse response = client.execute(request);
            
            // 忽略响应码校验
            ByteArrayOutputStream output = new ByteArrayOutputStream();
            IOUtils.copy(response.getEntity().getContent(), output);
            return output.toByteArray();
        }
    }
}