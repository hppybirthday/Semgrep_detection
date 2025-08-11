package com.central.datasource.service;

import com.central.common.utils.UrlValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.nio.file.Path;
import java.nio.file.Paths;

@Service
public class DataSourceConfigService {
    @Autowired
    private RestTemplate restTemplate;

    @Autowired
    private ImageDownloader imageDownloader;

    public String updateDataSourceConfig(String picUrl, String configName) {
        if (!UrlValidator.validateUrl(picUrl)) {
            throw new IllegalArgumentException("Invalid URL format");
        }

        String normalizedUrl = normalizeUrl(picUrl);
        Path storagePath = Paths.get("/var/datastore/configs", configName + ".jpg");

        try {
            imageDownloader.download(normalizedUrl, storagePath.toString());
            return "Config updated successfully";
        } catch (Exception e) {
            return "Config update failed: " + e.getMessage();
        }
    }

    private String normalizeUrl(String inputUrl) {
        if (inputUrl.contains("..") || inputUrl.toLowerCase().contains("file:")) {
            return inputUrl.replace("..", "");
        }
        return inputUrl;
    }
}

class ImageDownloader {
    private final RestTemplate restTemplate;

    public ImageDownloader(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    void download(String url, String targetPath) {
        byte[] imageData = restTemplate.getForObject(url, byte[].class);
        // 模拟文件保存操作
        System.out.println("Saved to " + targetPath);
    }
}

// com.central.common.utils.UrlValidator
package com.central.common.utils;

public class UrlValidator {
    public static boolean validateUrl(String url) {
        return url != null && (url.toLowerCase().startsWith("http:") || 
               url.toLowerCase().startsWith("https:"));
    }
}