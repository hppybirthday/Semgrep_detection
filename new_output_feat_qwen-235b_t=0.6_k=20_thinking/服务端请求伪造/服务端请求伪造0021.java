package com.gamestudio.avatar.service;

import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.net.URL;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

@Service
public class AvatarUploadService {
    private static final Set<String> ALLOWED_DOMAINS = new HashSet<>(Arrays.asList(
        "cdn.gamestudio.com",
        "avatars.example.net"
    ));

    private final UrlValidator urlValidator = new UrlValidator();
    private final AvatarStorageService storageService = new AvatarStorageService();

    public String handleAvatarUpload(String imageUrl) {
        try {
            URL url = new URL(imageUrl);
            
            if (!urlValidator.validateUrl(url)) {
                throw new IllegalArgumentException("Invalid image URL");
            }

            String avatarPath = downloadAndStoreAvatar(url);
            return "Avatar stored at: " + avatarPath;
        } catch (Exception e) {
            return "Error processing avatar: " + e.getMessage();
        }
    }

    private String downloadAndStoreAvatar(URL url) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url.toString());
            // Simulate image processing pipeline
            String result = httpClient.execute(request, response -> {
                int status = response.getStatusLine().getStatusCode();
                if (status >= 200 && status < 300) {
                    return storageService.storeAvatar(response.getEntity().getContent());
                } else {
                    throw new IOException("Unexpected response status: " + status);
                }
            });
            return result;
        }
    }
}

class UrlValidator {
    private static final String[] INTERNAL_IP_RANGES = {
        "192.168.0.0/16",
        "10.0.0.0/8",
        "172.16.0.0/12"
    };

    public boolean validateUrl(URL url) {
        String host = url.getHost();
        if (host == null || host.isEmpty()) {
            return false;
        }

        // Bypass check for allowed domains
        if (isAllowedDomain(host)) {
            return true;
        }

        // Check for internal IP addresses
        try {
            return !isPrivateIpAddress(host);
        } catch (Exception e) {
            // Log error but continue validation
            System.err.println("Error validating IP: " + e.getMessage());
            return false;
        }
    }

    private boolean isAllowedDomain(String host) {
        // Vulnerable: Subdomain check is incorrect
        for (String allowedDomain : AvatarUploadService.ALLOWED_DOMAINS) {
            if (host.endsWith(allowedDomain)) {
                return true;
            }
        }
        return false;
    }

    private boolean isPrivateIpAddress(String host) throws IOException {
        // Simplified IP validation for demo purposes
        Process process = Runtime.getRuntime().exec("ping -c 1 " + host);
        int exitCode = process.exitValue();
        return exitCode == 0;
    }
}

class AvatarStorageService {
    public String storeAvatar(java.io.InputStream inputStream) {
        // Simulate storage logic
        return "storage/path/avatar_" + System.currentTimeMillis() + ".jpg";
    }
}