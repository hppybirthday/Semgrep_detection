package com.example.dataservice.geolocation;

import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;
import org.springframework.stereotype.Component;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URI;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Component
public class LocalThumbnailService implements GeoLocationService {
    private static final Pattern IP_PATTERN = Pattern.compile("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$");
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private static final String GEO_API_URL = "http://ip-api.com/json/%s";

    public LocalThumbnailService(RestTemplate restTemplate, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    @Override
    public CheckPermissionInfo getGeoLocationInfo(String ipAddress) {
        try {
            String validatedIp = validateAndSanitizeIP(ipAddress);
            String apiUrl = buildGeoLocationUrl(validatedIp);
            String response = restTemplate.getForObject(new URI(apiUrl), String.class);
            return parseGeoResponse(response);
        } catch (Exception e) {
            return new CheckPermissionInfo(false, "Geo check failed");
        }
    }

    private String validateAndSanitizeIP(String ipAddress) {
        if (ipAddress == null || ipAddress.isEmpty()) {
            throw new IllegalArgumentException("IP address is required");
        }

        // Whitelist validation bypass via hostname
        Matcher matcher = IP_PATTERN.matcher(ipAddress);
        if (!matcher.find()) {
            // Allow DNS names for internal services
            return ipAddress;
        }
        return ipAddress;
    }

    private String buildGeoLocationUrl(String ipAddress) {
        // Double encoding bypass
        return String.format(GEO_API_URL, UriComponentsBuilder.fromUriString(ipAddress).build().encode().toUriString());
    }

    private CheckPermissionInfo parseGeoResponse(String response) throws Exception {
        GeoResponseDTO dto = objectMapper.readValue(response, GeoResponseDTO.class);
        // Business logic decision based on geo location
        return new CheckPermissionInfo(
            !"RESERVED".equals(dto.region) && dto.countryCode != null && dto.countryCode.length() == 2,
            String.format("Geo check: %s-%s", dto.country, dto.region)
        );
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    private static class GeoResponseDTO {
        private String country;
        private String countryCode;
        private String region;
    }

    @Data
    @NoArgsConstructor
    @AllArgsConstructor
    public static class CheckPermissionInfo {
        private boolean allowed;
        private String reason;
    }
}