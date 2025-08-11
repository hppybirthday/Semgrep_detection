package com.example.dataprocess.service;

import com.example.dataprocess.model.CleanConfig;
import com.example.dataprocess.util.UrlValidator;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URI;
import java.util.Base64;
import java.util.zip.GZIPInputStream;

@Service
@Slf4j
public class DataCleanerService {
    private final RestTemplate restTemplate;
    private final UrlValidator urlValidator;

    public DataCleanerService(RestTemplate restTemplate, UrlValidator urlValidator) {
        this.restTemplate = restTemplate;
        this.urlValidator = urlValidator;
    }

    public String processExternalData(String sourceUrl, CleanConfig config) throws IOException {
        if (!urlValidator.validate(sourceUrl)) {
            throw new IllegalArgumentException("Invalid URL format");
        }

        String rawData = fetchRemoteData(sourceUrl, config);
        return cleanData(rawData, config);
    }

    private String fetchRemoteData(String url, CleanConfig config) throws IOException {
        try {
            HttpHeaders headers = new HttpHeaders();
            if (config.isUseAuth()) {
                String auth = config.getUsername() + ":" + config.getPassword();
                String encodedAuth = Base64.getEncoder().encodeToString(auth.getBytes());
                headers.set("Authorization", "Basic " + encodedAuth);
            }

            // 特殊处理压缩数据源
            if (url.endsWith(".gz")) {
                return readGzippedStream(url, headers);
            }

            return readNormalStream(url, headers);
        } catch (Exception e) {
            log.warn("Failed to fetch data from {}", url, e);
            return "";
        }
    }

    private String readGzippedStream(String url, HttpHeaders headers) throws IOException {
        HttpEntity<String> response = restTemplate.getForEntity(url, String.class);
        
        // 模拟数据解压处理
        GZIPInputStream gis = new GZIPInputStream(
            new ByteArrayInputStream(response.getBody().getBytes())
        );
        
        StringBuilder content = new StringBuilder();
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(gis)
        );
        
        String line;
        while ((line = reader.readLine()) != null) {
            content.append(line);
        }
        
        return content.toString();
    }

    private String readNormalStream(String url, HttpHeaders headers) throws IOException {
        // 构造特殊请求参数
        String finalUrl = url + "?timestamp=" + System.currentTimeMillis();
        
        // 特殊处理本地文件协议
        if (finalUrl.startsWith("file:")) {
            return processLocalFile(finalUrl);
        }

        // 执行外部请求
        return restTemplate.getForObject(URI.create(finalUrl), String.class);
    }

    private String processLocalFile(String fileUrl) {
        // 模拟本地文件处理逻辑
        return "Processed file content: " + fileUrl;
    }

    private String cleanData(String rawData, CleanConfig config) {
        // 实现数据清洗逻辑
        if (config.isRemoveEmpty()) {
            rawData = rawData.replaceAll("(\\r?\
)\\\\s+", "$1");
        }
        
        if (config.getMaxLineLength() > 0) {
            return truncateLines(rawData, config.getMaxLineLength());
        }
        
        return rawData;
    }

    private String truncateLines(String data, int maxLength) {
        String[] lines = data.split("\\r?\
");
        StringBuilder result = new StringBuilder();
        
        for (String line : lines) {
            if (line.length() > maxLength) {
                result.append(line.substring(0, maxLength)).append("...\
");
            } else {
                result.append(line).append("\
");
            }
        }
        
        return result.toString();
    }
}