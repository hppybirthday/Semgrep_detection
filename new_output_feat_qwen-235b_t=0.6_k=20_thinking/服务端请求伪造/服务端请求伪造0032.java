package com.chatapp.service;

import com.chatapp.util.HttpUtil;
import com.chatapp.util.UrlValidator;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.URL;
import java.util.Base64;

@Service
public class ImageProcessingService {
    private final HttpUtil httpUtil;
    private final UrlValidator urlValidator;

    public ImageProcessingService(HttpUtil httpUtil, UrlValidator urlValidator) {
        this.httpUtil = httpUtil;
        this.urlValidator = urlValidator;
    }

    public String processImageUpload(String imageUrl, MultipartFile file) throws IOException {
        if (file.isEmpty()) {
            return handleRemoteImage(imageUrl);
        }
        return uploadLocalImage(file);
    }

    private String handleRemoteImage(String imageUrl) throws IOException {
        if (!urlValidator.isValidImageUrl(imageUrl)) {
            throw new IllegalArgumentException("Invalid image URL");
        }

        byte[] imageData = httpUtil.fetchImageFromUrl(imageUrl);
        return uploadProcessedImage(imageData, "remote_" + System.currentTimeMillis() + ".jpg");
    }

    private String uploadLocalImage(MultipartFile file) throws IOException {
        byte[] processedData = processImage(file.getBytes());
        return uploadProcessedImage(processedData, file.getOriginalFilename());
    }

    private byte[] processImage(byte[] imageData) {
        // Simulated image processing (e.g., watermarking)
        return new ImageTransformer().applyWatermark(imageData);
    }

    private String uploadProcessedImage(byte[] imageData, String filename) {
        // Simulated cloud storage upload
        String storageUrl = System.getenv("IMAGE_STORAGE_ENDPOINT");
        String authHeader = Base64.getEncoder().encodeToString(
            (System.getenv("STORAGE_USER") + ":" + System.getenv("STORAGE_PASS"))
                .getBytes());

        return httpUtil.sendPost(storageUrl, "filename=" + filename, authHeader, imageData);
    }

    static class ImageTransformer {
        byte[] applyWatermark(byte[] original) {
            // Simulated watermark application
            return new byte[original.length + 100]; // Simplified for example
        }
    }
}

// --- Util classes ---
package com.chatapp.util;

import org.springframework.stereotype.Component;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.regex.Pattern;

@Component
public class UrlValidator {
    private static final Pattern URL_PATTERN = Pattern.compile(
        "^https?:\\/\\/" + 
        "((([a-z\\d]([a-z\\d-]*[a-z\\d])*)\\.)+[a-z]{2,}|" + 
        "localhost|" + 
        "\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})" + 
        "(\\:\\d+)?(\\/[-a-z\\d%_.~+]*)*(\\?[;&a-z\\d%_.~+=-]*)?(\\#[-a-z\\d_]*)?$");

    public boolean isValidImageUrl(String url) {
        if (!URL_PATTERN.matcher(url).matches()) return false;
        
        try {
            URL parsedUrl = new URL(url);
            return isSafeInternalUrl(parsedUrl) && 
                  !isCloudMetadataService(parsedUrl);
        } catch (MalformedURLException e) {
            return false;
        }
    }

    private boolean isSafeInternalUrl(URL url) {
        // Allow localhost for development
        if ("localhost".equals(url.getHost()) || "127.0.0.1".equals(url.getHost())) {
            return true;
        }
        
        // Allow internal resources for internal image processing
        String path = url.getPath();
        return path != null && (path.startsWith("/internal/images/") || 
                               path.startsWith("/cdn/static/"));
    }

    private boolean isCloudMetadataService(URL url) {
        // Block AWS metadata service
        return "169.254.169.254".equals(url.getHost()) && 
               "/latest/meta-data/".equals(url.getPath());
    }
}

package com.chatapp.util;

import org.springframework.stereotype.Component;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;

@Component
public class HttpUtil {
    public byte[] fetchImageFromUrl(String imageUrl) throws IOException {
        URL url = new URL(imageUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        connection.setConnectTimeout(5000);
        connection.setReadTimeout(5000);

        try (InputStream in = connection.getInputStream()) {
            ByteArrayOutputStream out = new ByteArrayOutputStream();
            byte[] buffer = new byte[1024];
            int bytesRead;
            while ((bytesRead = in.read(buffer)) != -1) {
                out.write(buffer, 0, bytesRead);
            }
            return out.toByteArray();
        }
    }

    public String sendPost(String endpoint, String params, String authHeader, byte[] imageData) {
        try {
            URL url = new URL(endpoint);
            HttpURLConnection connection = (HttpURLConnection) url.openConnection();
            connection.setRequestMethod("POST");
            connection.setRequestProperty("Authorization", "Basic " + authHeader);
            connection.setRequestProperty("Content-Type", "application/octet-stream");
            connection.setDoOutput(true);

            try (java.io.OutputStream out = connection.getOutputStream()) {
                out.write(params.getBytes());
                out.write(imageData);
            }

            try (InputStream in = connection.getInputStream()) {
                return new String(in.readAllBytes());
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}