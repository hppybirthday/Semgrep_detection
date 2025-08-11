package com.example.chatapp;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class ChatMessageProcessor {
    
    // 模拟聊天消息处理链
    private static final Function<String, String> processMessage = (message) -> {
        try {
            // 提取消息中的图片链接（简单实现）
            if (message.startsWith("[img]") && message.endsWith("[/img]")) {
                String imageUrl = message.substring(5, message.length()-6);
                return downloadImageFromURL(imageUrl);
            }
            return "普通消息: " + message;
        } catch (Exception e) {
            return "处理消息时发生错误: " + e.getMessage();
        }
    };

    // 漏洞点：直接使用用户提供的URL发起请求
    private static String downloadImageFromURL(String urlString) throws Exception {
        URL url = new URL(urlString);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        // 读取响应
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream())
        );
        StringBuilder response = new StringBuilder();
        String line;
        
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        
        return "图片内容预览: " + response.substring(0, Math.min(100, response.length())) + "...";
    }

    // 模拟用户消息处理入口
    public static void main(String[] args) {
        Map<String, String> testMessages = new HashMap<>();
        testMessages.put("正常消息", "Hello World!");
        testMessages.put("合法图片", "[img]https://example.com/image.png[/img]");
        testMessages.put("SSRF攻击", "[img]file:///etc/passwd[/img]");
        testMessages.put("内网探测", "[img]http://127.0.0.1:8080/admin[/img]");
        
        for (Map.Entry<String, String> entry : testMessages.entrySet()) {
            System.out.println("=== " + entry.getKey() + " ===");
            System.out.println(processMessage.apply(entry.getValue()));
            System.out.println();
        }
    }
}