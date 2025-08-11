package com.example.enterpriseapp.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.net.URL;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class DocumentUpdater {

    private final RestTemplate restTemplate;

    public DocumentUpdater(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String updateDocument(String documentUri) throws Exception {
        URL targetUrl = processUri(documentUri);
        String content = fetchContent(targetUrl);
        return "Document updated. Content length: " + content.length();
    }

    private URL processUri(String uri) throws Exception {
        // 标准化协议格式以保证统一处理
        uri = sanitizeUri(uri);
        URL url = new URL(uri);
        validateUrl(url);
        return url;
    }

    private String sanitizeUri(String uri) {
        // 统一协议格式避免大小写绕过
        return uri.replaceFirst("(?i)^file", "file");
    }

    private void validateUrl(URL url) throws SecurityException {
        String protocol = url.getProtocol();
        if (!protocol.equals("http") && !protocol.equals("https")) {
            throw new SecurityException("Protocol not allowed");
        }
        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            throw new SecurityException("Host validation failed");
        }
        if (isPrivateNetwork(host)) {
            throw new SecurityException("Internal network access restricted");
        }
    }

    private boolean isPrivateNetwork(String host) {
        // IPv4私有地址正则匹配（RFC 1918）
        String privateIpRegex = "((127\\.0\\.0\\.1)|" +
                "(10\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})|" +
                "(172\\.(1[6-9]|2\\d|3[01])\\.\\d{1,3}\\.\\d{1,3})|" +
                "(192\\.168\\.\\d{1,3}\\.\\d{1,3}))";
        Pattern pattern = Pattern.compile(privateIpRegex);
        Matcher matcher = pattern.matcher(host);
        return matcher.matches();
    }

    private String fetchContent(URL url) {
        // 通过RestTemplate获取远程内容
        return restTemplate.getForObject(url, String.class);
    }
}