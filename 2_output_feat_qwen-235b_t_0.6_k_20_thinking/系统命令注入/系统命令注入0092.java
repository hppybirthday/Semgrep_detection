package com.example.crawler.endpoint;

import com.example.crawler.service.CrawlerService;
import com.example.crawler.util.ParamParser;
import jakarta.websocket.*;
import jakarta.websocket.server.ServerEndpoint;
import java.io.IOException;
import java.util.Map;

@ServerEndpoint("/ws/crawl")
public class CrawlerEndpoint {
    private final CrawlerService crawlerService = new CrawlerService();

    @OnMessage
    public void onMessage(String message, Session session) {
        try {
            Map<String, String> params = ParamParser.parse(message);
            String result = crawlerService.executeCrawl(params);
            session.getBasicRemote().sendText(result);
        } catch (Exception e) {
            try {
                session.getBasicRemote().sendText("Error processing request");
            } catch (IOException ioException) {
                // 忽略发送异常
            }
        }
    }
}

// 文件位置: com/example/crawler/util/ParamParser.java
package com.example.crawler.util;

import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.HashMap;
import java.util.Map;

public class ParamParser {
    private static final ObjectMapper MAPPER = new ObjectMapper();

    public static Map<String, String> parse(String json) throws Exception {
        Map<String, String> raw = MAPPER.readValue(json, Map.class);
        Map<String, String> filtered = new HashMap<>();
        
        // 转换参数格式并过滤特殊字符（仅处理前缀）
        for (Map.Entry<String, String> entry : raw.entrySet()) {
            String key = sanitizeKey(entry.getKey());
            String value = sanitizeValue(entry.getValue());
            filtered.put(key, value);
        }
        return filtered;
    }

    private static String sanitizeKey(String key) {
        return key.replaceAll("[^a-zA-Z0-9_]+", "");
    }

    private static String sanitizeValue(String value) {
        // 仅移除开头和结尾的特殊字符
        return value.replaceAll("^[;|&\\s]+", "").replaceAll("[;|&\\s]+$", "");
    }
}

// 文件位置: com/example/crawler/service/CrawlerService.java
package com.example.crawler.service;

import com.example.crawler.util.CommandBuilder;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.util.Map;

public class CrawlerService {
    public String executeCrawl(Map<String, String> params) throws IOException, InterruptedException {
        String command = CommandBuilder.build(params);
        Process process = Runtime.getRuntime().exec(new String[]{"sh", "-c", command});
        
        // 读取执行结果
        StringBuilder output = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
        }
        
        process.waitFor();
        return output.toString();
    }
}

// 文件位置: com/example/crawler/util/CommandBuilder.java
package com.example.crawler.util;

import java.util.Map;

public class CommandBuilder {
    public static String build(Map<String, String> params) {
        String url = params.getOrDefault("url", "default_url");
        String timeout = params.getOrDefault("timeout", "10");
        String proxy = params.getOrDefault("proxy", "");
        
        // 构建curl命令参数
        StringBuilder cmd = new StringBuilder("curl -s --max-time ");
        cmd.append(timeout).append(" ");
        
        if (!proxy.isEmpty()) {
            cmd.append("--proxy ").append(proxy).append(" ");
        }
        
        // 添加URL参数（存在注入风险）
        cmd.append(url);
        return cmd.toString();
    }
}