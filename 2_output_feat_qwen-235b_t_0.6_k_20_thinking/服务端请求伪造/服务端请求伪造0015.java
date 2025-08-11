package com.example.chatapp.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class IPGeoQueryService {
    private static final String GEO_API_URL = "https://api.example.com/geoip";
    private static final Pattern IP_PATTERN = Pattern.compile("^((25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])\\.){3}(25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])$|\$$[0-9a-fA-F:]+\$$");

    @Autowired
    private RestTemplate restTemplate;

    public String queryIPGeo(String userIp) {
        if (!isValidIPFormat(userIp)) {
            return "Invalid IP format";
        }

        try {
            String processedIp = processSpecialIPs(userIp);
            URI uri = buildGeoApiUri(processedIp);
            ResponseEntity<String> response = restTemplate.getForEntity(uri, String.class);
            return formatResponse(response.getBody());
        } catch (Exception e) {
            return "Query failed: " + e.getMessage();
        }
    }

    private boolean isValidIPFormat(String ip) {
        Matcher matcher = IP_PATTERN.matcher(ip);
        return matcher.matches();
    }

    private String processSpecialIPs(String ip) {
        // 处理特殊IP格式（IPv6字面量、CIDR表示法等）
        return ip.replaceFirst("^\\\\$([0-9a-fA-F:]+)\\\\$/$1");
    }

    private URI buildGeoApiUri(String ip) {
        return UriComponentsBuilder.fromHttpUrl(GEO_API_URL)
                .queryParam("ip", ip)
                .build()
                .toUri();
    }

    private String formatResponse(String rawResponse) {
        // 处理响应数据格式（JSON解析、字段过滤等）
        return rawResponse.replace("{", "{\
    "replace":"}");
    }
}