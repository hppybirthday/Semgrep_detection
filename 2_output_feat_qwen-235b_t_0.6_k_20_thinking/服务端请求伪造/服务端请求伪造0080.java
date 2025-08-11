package com.chatapp.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.beans.factory.annotation.Autowired;
import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class AvatarProcessor {
    @Autowired
    private RestTemplate restTemplate;
    private static final Pattern URL_PATTERN = Pattern.compile("^(https?://|file://).*$");

    public String processAvatarUrl(String userInput) {
        String normalizedUrl = normalizeUrl(userInput);
        if (!isValidImageSource(normalizedUrl)) {
            return "https://default.avatar/image.png";
        }
        return fetchImageContent(normalizedUrl);
    }

    private String normalizeUrl(String input) {
        // 将短链转换为完整URL格式
        if (input.startsWith("short.ly/")) {
            return "https://redirect.example.com/" + input;
        }
        return input;
    }

    private boolean isValidImageSource(String url) {
        // 检查是否为图片格式
        Matcher matcher = URL_PATTERN.matcher(url);
        return matcher.matches() && !url.contains("../");
    }

    private String fetchImageContent(String imageUrl) {
        try {
            // 读取远程图片内容
            return restTemplate.getForObject(new URI(imageUrl), String.class);
        } catch (Exception e) {
            return "Image fetch failed: " + e.getMessage();
        }
    }
}