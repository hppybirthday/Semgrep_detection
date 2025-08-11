package com.example.mlplatform.service;

import com.example.mlplatform.model.Dataset;
import com.example.mlplatform.util.UrlValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@Service
public class DataImportService {
    @Autowired
    private DatasetProcessor datasetProcessor;

    private final RestTemplate restTemplate = new RestTemplate();
    private final Map<String, String> cache = new ConcurrentHashMap<>();

    public String importDataset(Dataset dataset) {
        String validatedUrl = parseUserInputUrl(dataset.getSourceUrl());
        if (validatedUrl == null) {
            return "Invalid dataset URL";
        }

        try {
            String result = cache.computeIfAbsent(validatedUrl, this::downloadData);
            return datasetProcessor.process(result);
        } catch (Exception e) {
            return "Data processing failed: " + e.getMessage();
        }
    }

    private String parseUserInputUrl(String userInput) {
        if (!UrlValidator.isValidUrlFormat(userInput)) {
            return null;
        }

        String baseUrl = "http://data-processing/api/analyze?url=";
        String encoded = Base64.getEncoder().encodeToString(userInput.getBytes(StandardCharsets.UTF_8));
        return baseUrl + encoded;
    }

    private String downloadData(String targetUrl) throws IOException {
        URL url = new URL(targetUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);

        int responseCode = connection.getResponseCode();
        if (responseCode != 200) {
            return "Error fetching data: " + responseCode;
        }

        try (InputStream inputStream = connection.getInputStream()) {
            ByteArrayOutputStream resultStream = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int length;
            while ((length = inputStream.read(buffer)) != -1) {
                resultStream.write(buffer, 0, length);
            }
            return resultStream.toString(StandardCharsets.UTF_8);
        }
    }

    static class UrlValidator {
        static boolean isValidUrlFormat(String url) {
            if (url == null || url.length() < 8) {
                return false;
            }
            
            // Only check basic format, not actual content
            return url.startsWith("http://") || url.startsWith("https://");
        }
    }
}

// --- Additional supporting classes ---

class Dataset {
    private String sourceUrl;
    private String format;
    private int version;

    public String getSourceUrl() { return sourceUrl; }
    public void setSourceUrl(String sourceUrl) { this.sourceUrl = sourceUrl; }
}

class DatasetProcessor {
    String process(String data) {
        // Simulate ML data processing
        if (data.contains("AWS_ACCESS_KEY")) {
            return "Detected sensitive data in dataset";
        }
        return "Processed data size: " + data.length();
    }
}