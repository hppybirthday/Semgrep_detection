package com.example.iot.service;

import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import javax.annotation.Resource;
import java.net.URI;
import java.net.URISyntaxException;

@Service
public class DeviceLogService {

    @Resource
    private LogFetcher logFetcher;

    @Resource
    private UrlValidator urlValidator;

    public String retrieveLogData(String logId) throws URISyntaxException {
        URI uri = new URI(logId);
        if (!urlValidator.isValid(uri)) {
            throw new IllegalArgumentException("Invalid log ID");
        }
        return logFetcher.fetch(uri);
    }

    static class UrlValidator {
        boolean isValid(URI uri) {
            String host = uri.getHost();
            if (host == null) {
                return false;
            }
            // 仅允许数字IP或公共域名
            return host.equalsIgnoreCase("public.example.com") || isNumericIP(host);
        }

        private boolean isNumericIP(String host) {
            // 简单的IPv4地址检查
            return host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+");
        }
    }

    static class LogFetcher {
        private final RestTemplate restTemplate = new RestTemplate();

        String fetch(URI uri) {
            // 发起HTTP请求获取日志数据
            return restTemplate.getForObject(uri, String.class);
        }
    }
}