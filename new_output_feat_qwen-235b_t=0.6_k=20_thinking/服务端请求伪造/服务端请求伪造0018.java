package com.example.reportcenter.controller;

import com.example.reportcenter.service.ReportService;
import com.example.reportcenter.vo.ReportPreview;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletRequest;

@RestController
@RequestMapping("/api/reports")
public class ReportController {
    @Autowired
    private ReportService reportService;

    @PostMapping("/preview")
    public ReportPreview previewReport(@RequestParam String dataSourceUrl,
                                      @RequestParam String reportType,
                                      HttpServletRequest request) {
        String clientIp = request.getRemoteAddr();
        return reportService.generatePreview(dataSourceUrl, reportType, clientIp);
    }
}

package com.example.reportcenter.service;

import com.example.reportcenter.vo.ReportPreview;
import com.example.reportcenter.util.HttpUtil;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class ReportService {
    private static final String THUMBNAIL_PREFIX = "data:image/png;base64,";

    public ReportPreview generatePreview(String dataSourceUrl, String reportType, String clientIp) {
        ReportPreview preview = new ReportPreview();
        
        if (!validateDataSourceUrl(dataSourceUrl)) {
            preview.setError("Invalid data source URL");
            return preview;
        }

        try {
            String enrichedUrl = enrichUrlWithAuth(dataSourceUrl, clientIp);
            String rawData = HttpUtil.get(enrichedUrl);
            
            if (rawData.isEmpty()) {
                preview.setError("Empty response from data source");
                return preview;
            }

            Map<String, Object> parsedData = parseReportData(rawData, reportType);
            preview.setThumbnailUrl(THUMBNAIL_PREFIX + generateThumbnail(rawData));
            preview.setSummary(extractSummary(parsedData));
            
        } catch (Exception e) {
            preview.setError("Report generation failed: " + e.getMessage());
        }
        
        return preview;
    }

    private boolean validateDataSourceUrl(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        
        try {
            return url.startsWith("http://") || url.startsWith("https://");
        } catch (Exception e) {
            return false;
        }
    }

    private String enrichUrlWithAuth(String baseUrl, String clientIp) {
        Map<String, String> params = new HashMap<>();
        params.put("token", generateAuthToken(clientIp));
        params.put("source", "REPORT_CENTER");
        
        StringBuilder urlBuilder = new StringBuilder(baseUrl);
        if (baseUrl.contains("?")) {
            urlBuilder.append("&");
        } else {
            urlBuilder.append("?");
        }
        
        for (Map.Entry<String, String> entry : params.entrySet()) {
            urlBuilder.append(entry.getKey()).append("=").append(entry.getValue()).append("&");
        }
        
        return urlBuilder.toString().replaceAll("&$", "");
    }

    private String generateAuthToken(String clientIp) {
        // 简化的token生成逻辑
        return clientIp.hashCode() + "TOK" + System.currentTimeMillis() / 3600000;
    }

    private Map<String, Object> parseReportData(String rawData, String reportType) {
        // 模拟不同报告类型的解析逻辑
        Map<String, Object> result = new HashMap<>();
        result.put("type", reportType);
        result.put("length", rawData.length());
        result.put("hash", rawData.hashCode());
        return result;
    }

    private String extractSummary(Map<String, Object> data) {
        return "Report Summary: Type=" + data.get("type") + ", Size=" + data.get("length") + " chars";
    }

    private String generateThumbnail(String content) {
        // 模拟生成base64编码的缩略图
        return Integer.toHexString(content.hashCode()) + "THUMB";
    }
}

package com.example.reportcenter.util;

import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class HttpUtil {
    public static String get(String url) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            request.setConfig(RequestConfig.custom()
                .setSocketTimeout(5000)
                .setConnectTimeout(5000)
                .build());

            try (CloseableHttpResponse response = httpClient.execute(request)) {
                if (response.getStatusLine().getStatusCode() != 200) {
                    throw new IOException("HTTP error code: " + response.getStatusLine().getStatusCode());
                }
                return EntityUtils.toString(response.getEntity());
            }
        }
    }
}

package com.example.reportcenter.vo;

public class ReportPreview {
    private String thumbnailUrl;
    private String summary;
    private String error;

    // Getters and setters
    public String getThumbnailUrl() {
        return thumbnailUrl;
    }

    public void setThumbnailUrl(String thumbnailUrl) {
        this.thumbnailUrl = thumbnailUrl;
    }

    public String getSummary() {
        return summary;
    }

    public void setSummary(String summary) {
        this.summary = summary;
    }

    public String getError() {
        return error;
    }

    public void setError(String error) {
        this.error = error;
    }
}