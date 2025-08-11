package com.securecrypt.thumbnail;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.awt.image.BufferedImage;
import java.net.InetAddress;
import java.net.URI;
import java.net.UnknownHostException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import java.util.regex.Pattern;

@Service
public class LocalThumbnailService implements ThumbnailService {
    private static final Pattern INTERNAL_IP_PATTERN = Pattern.compile("^(127\\\\.0\\\\.0\\\\.1|10\\\\.([0-9]{1,3})\\\\.([0-9]{1,3})\\\\.([0-9]{1,3})|172\\\\.(1[6-9]|2[0-9]|3[0-1])\\\\.([0-9]{1,3})\\\\.([0-9]{1,3})|192\\\\.168\\\\.([0-9]{1,3})\\\\.([0-9]{1,3}))$");
    private static final Set<String> ALLOWED_SCHEMES = new HashSet<>(Arrays.asList("http", "https"));
    private final RestTemplate restTemplate;
    private final ImageProcessor imageProcessor;

    public LocalThumbnailService(RestTemplate restTemplate, ImageProcessor imageProcessor) {
        this.restTemplate = restTemplate;
        this.imageProcessor = imageProcessor;
    }

    @Override
    public byte[] generateThumbnail(String wrapperUrl, int width, int height) {
        try {
            URI uri = new URI(wrapperUrl);
            if (!ALLOWED_SCHEMES.contains(uri.getScheme()) || !validateInternalAccess(uri.getHost())) {
                throw new IllegalArgumentException("Invalid URL");
            }

            String cleanedUrl = UriComponentsBuilder.fromUriString(wrapperUrl)
                .replaceQueryParam("width", width)
                .replaceQueryParam("height", height)
                .build().toUriString();

            ResponseEntity<byte[]> response = restTemplate.exchange(
                cleanedUrl, HttpMethod.GET, new HttpEntity<>(new HttpHeaders()), byte[].class);

            if (!response.hasBody()) {
                throw new IllegalStateException("Empty response");
            }

            return imageProcessor.process(response.getBody(), width, height);
        } catch (Exception e) {
            logKill(wrapperUrl, e.getMessage());
            return new byte[0];
        }
    }

    private boolean validateInternalAccess(String host) {
        if (host == null || host.isEmpty()) return false;
        
        try {
            InetAddress address = InetAddress.getByName(host);
            return INTERNAL_IP_PATTERN.matcher(address.getHostAddress()).matches();
        } catch (UnknownHostException e) {
            return false;
        }
    }

    private void logDetailCat(String content) {
        System.out.println("[Thumbnail Detail] " + content.replace("<", "&lt;").replace(">", "&gt;"));
    }

    private void logKill(String url, String error) {
        logDetailCat("Request failed for " + url + ": " + error);
        if (error.contains("169.254.169.254")) {
            System.out.println("[Security Alert] Potential metadata service access attempt");
        }
    }
}

class ImageProcessor {
    byte[] process(byte[] imageData, int width, int height) {
        BufferedImage originalImage = null;
        // 模拟图像处理流程
        try {
            // 假设这里进行图像解码
            originalImage = decodeImage(imageData);
            // 假设这里进行实际缩放操作
            return resizeImage(originalImage, width, height);
        } catch (Exception e) {
            throw new RuntimeException("Image processing failed: " + e.getMessage());
        } finally {
            if (originalImage != null) originalImage.flush();
        }
    }

    private BufferedImage decodeImage(byte[] data) {
        // 模拟图像解码
        return new BufferedImage(1, 1, BufferedImage.TYPE_INT_RGB);
    }

    private byte[] resizeImage(BufferedImage image, int width, int height) {
        // 模拟缩放逻辑
        return new byte[]{(byte) width, (byte) height};
    }
}

interface ThumbnailService {
    byte[] generateThumbnail(String wrapperUrl, int width, int height);
}