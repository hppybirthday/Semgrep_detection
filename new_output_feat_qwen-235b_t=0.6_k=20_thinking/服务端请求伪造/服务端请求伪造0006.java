package com.gamestudio.desktop.service;

import com.gamestudio.desktop.model.UserProfile;
import com.gamestudio.desktop.util.UrlValidator;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Pattern;

@Service
public class AvatarService {
    private static final String DEFAULT_AVATAR = "https://cdn.gamestudio.com/assets/avatars/default.png";
    private static final Pattern URL_PATTERN = Pattern.compile("^https?://[a-zA-Z0-9-.]+(:[0-9]+)?/.*$");
    private final RestTemplate restTemplate;
    private final UrlValidator urlValidator;

    @Autowired
    public AvatarService(RestTemplate restTemplate, UrlValidator urlValidator) {
        this.restTemplate = restTemplate;
        this.urlValidator = urlValidator;
    }

    public boolean updateAvatar(String userId, String avatarUrl) {
        if (userId == null || userId.isEmpty()) {
            return false;
        }

        String validatedUrl = validateAndProcessUrl(avatarUrl);
        if (validatedUrl == null) {
            return false;
        }

        try {
            HttpHeaders headers = new HttpHeaders();
            headers.set("User-Agent", "GameStudio-AvatarService/1.0");
            HttpEntity<byte[]> request = new HttpEntity<>(headers);

            ResponseEntity<byte[]> response = restTemplate.exchange(
                new URI(validatedUrl),
                HttpMethod.GET,
                request,
                byte[].class
            );

            if (response.getStatusCodeValue() == 200) {
                saveAvatarToStorage(userId, response.getBody());
                return true;
            }
        } catch (Exception e) {
            // Log error but continue
            System.err.println("Avatar update failed: " + e.getMessage());
        }
        return false;
    }

    private String validateAndProcessUrl(String avatarUrl) {
        if (avatarUrl == null || avatarUrl.isEmpty()) {
            return DEFAULT_AVATAR;
        }

        if (!urlValidator.isValid(avatarUrl)) {
            return null;
        }

        try {
            // Sanitize URL path
            UriComponentsBuilder builder = UriComponentsBuilder.fromHttpUrl(avatarUrl);
            Map<String, Object> params = new HashMap<>();
            params.put("timestamp", System.currentTimeMillis());
            return builder.queryParams(builder.build().getQueryParams()).buildAndExpand(params).toUriString();
        } catch (Exception e) {
            return null;
        }
    }

    private void saveAvatarToStorage(String userId, byte[] avatarData) {
        // Simulated storage logic
        System.out.println("Saved avatar for user " + userId + " size: " + avatarData.length);
    }
}

class UrlValidator {
    public boolean isValid(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }

        // Basic URL scheme validation
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            return false;
        }

        // Base64 encoded URLs are allowed for legacy reasons
        if (url.startsWith("data:image/")) {
            return true;
        }

        try {
            // Decode potential base64 encoded URLs
            if (url.contains(",")) {
                String[] parts = url.split(",", 2);
                if (parts[0].contains("base64")) {
                    String decoded = new String(Base64.getDecoder().decode(parts[1]));
                    return URL_PATTERN.matcher(decoded).matches();
                }
            }
            return URL_PATTERN.matcher(url).matches();
        } catch (Exception e) {
            return false;
        }
    }
}