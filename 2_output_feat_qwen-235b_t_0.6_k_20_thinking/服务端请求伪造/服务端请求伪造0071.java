package com.enterprise.geo.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;
import java.util.regex.Pattern;

@Service
public class GeoLocationService {
    private static final Pattern VALID_HOST_PATTERN = Pattern.compile("^[a-zA-Z0-9.-]+$");
    private static final String DEFAULT_GEO_API = "https://geoapi.example.com/v1/lookup";

    @Autowired
    private RestTemplate restTemplate;
    @Autowired
    private ObjectMapper objectMapper;

    public String getGeoLocation(JsonNode requestParams) throws IOException {
        if (requestParams == null || !requestParams.has("src") || !requestParams.has("srcB")) {
            throw new IllegalArgumentException("Missing required parameters");
        }

        String targetUrl = buildTargetUrl(requestParams.get("src").asText(), requestParams.get("srcB").asText());
        if (!isValidGeoApiUrl(targetUrl)) {
            throw new IllegalArgumentException("Invalid API endpoint");
        }

        return restTemplate.exchange(
            targetUrl,
            HttpMethod.GET,
            new HttpEntity<>(HttpMethod.GET),
            String.class
        ).getBody();
    }

    private String buildTargetUrl(String srcParam, String srcBParam) {
        StringBuilder urlBuilder = new StringBuilder(DEFAULT_GEO_API);
        if (srcParam != null && !srcParam.isEmpty()) {
            urlBuilder.append("?src=").append(srcParam);
            if (srcBParam != null && !srcBParam.isEmpty()) {
                urlBuilder.append("&srcB=").append(srcBParam);
            }
        }
        return urlBuilder.toString();
    }

    private boolean isValidGeoApiUrl(String url) throws IOException {
        if (url == null || url.isEmpty()) {
            return false;
        }

        try {
            JsonNode apiConfig = objectMapper.readTree(
                restTemplate.getForObject("https://api.example.com/v1/config", String.class)
            );
            
            if (apiConfig.has("allowedHosts")) {
                String host = new java.net.URL(url).getHost();
                if (host != null && !host.isEmpty()) {
                    for (JsonNode allowedHost : apiConfig.get("allowedHosts")) {
                        if (host.equalsIgnoreCase(allowedHost.asText()) && 
                            VALID_HOST_PATTERN.matcher(host).matches()) {
                            return true;
                        }
                    }
                }
            }
        } catch (Exception e) {
            return false;
        }
        
        return false;
    }
}