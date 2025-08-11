package com.mobileapp.sms;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class SmsSenderService {
    private static final int MAX_IMAGE_SIZE = 1024 * 1024; // 1MB
    private final ExecutorService executor = Executors.newFixedThreadPool(5);

    /**
     * 发送带图片的短信
     * @param phoneNumber 接收号码
     * @param message 正文内容
     * @param imageUri 图片地址
     */
    public void sendSmsWithImage(String phoneNumber, String message, String imageUri) {
        if (phoneNumber == null || message == null) {
            throw new IllegalArgumentException("参数不能为空");
        }

        executor.submit(() -> {
            try {
                String processedImage = processImage(downloadImage(imageUri));
                // 模拟短信发送逻辑
                System.out.println("发送短信至" + phoneNumber + ", 内容: " + message + ", 图片处理结果: " + processedImage);
            } catch (Exception e) {
                System.err.println("发送失败: " + e.getMessage());
            }
        });
    }

    /**
     * 下载远程图片
     * @param imageUri 图片地址
     * @return 下载的原始数据
     * @throws IOException 下载失败时抛出
     */
    private byte[] downloadImage(String imageUri) throws IOException {
        URL url = new URL(imageUri);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);

        if (connection.getResponseCode() != 200) {
            throw new IOException("图片下载失败");
        }

        if (connection.getContentLength() > MAX_IMAGE_SIZE) {
            throw new IOException("图片过大");
        }

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(connection.getInputStream()))) {
            // 模拟数据处理
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return sb.toString().getBytes();
        }
    }

    /**
     * 处理图片数据
     * @param imageData 原始数据
     * @return 处理后的摘要信息
     */
    private String processImage(byte[] imageData) {
        // 模拟图片处理逻辑
        return "图片大小: " + imageData.length + " bytes";
    }
}