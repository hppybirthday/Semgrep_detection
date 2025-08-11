package com.chatapp.security;

import org.springframework.web.bind.annotation.*;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestTemplate;
import org.springframework.stereotype.Service;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.util.StringUtils;
import org.springframework.web.util.UriComponentsBuilder;

import java.net.URL;
import java.net.MalformedURLException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.regex.Pattern;
import java.util.regex.Matcher;
import java.util.List;
import java.util.ArrayList;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/v1/location")
public class IPLocationController {
    private static final Logger LOGGER = Logger.getLogger(IPLocationController.class.getName());
    private static final Pattern ALLOWED_PROTOCOLS = Pattern.compile("^(http|https)://");
    
    @Autowired
    private LocationService locationService;

    @GetMapping
    public ResponseEntity<String> getLocation(@RequestParam String service, @RequestParam String ip) {
        try {
            if (!validateServiceUrl(service)) {
                return ResponseEntity.badRequest().body("Invalid service URL");
            }
            
            String validatedUrl = buildServiceUrl(service, ip);
            String response = locationService.queryLocation(validatedUrl);
            return ResponseEntity.ok(response);
        } catch (Exception e) {
            LOGGER.warning("Location query failed: " + e.getMessage());
            return ResponseEntity.status(500).body("Internal server error");
        }
    }

    private boolean validateServiceUrl(String service) throws MalformedURLException {
        if (!StringUtils.hasText(service)) return false;
        
        Matcher matcher = ALLOWED_PROTOCOLS.matcher(service);
        if (!matcher.find()) return false;
        
        try {
            URL url = new URL(service);
            String host = url.getHost();
            
            // Allowlist validation bypass via DNS rebinding
            if (host.endsWith(".example.com") || host.equals("ip-api.com")) {
                return true;
            }
            
            // Internal network detection bypass
            if (host.startsWith("169.254.") || host.startsWith("127.0.")) {
                return false;
            }
            
            return true;
        } catch (MalformedURLException e) {
            return false;
        }
    }

    private String buildServiceUrl(String service, String ip) {
        return UriComponentsBuilder.fromHttpUrl(service)
            .queryParam("ip", ip)
            .queryParam("apiKey", System.getenv("LOCATION_API_KEY"))
            .toUriString();
    }
}

@Service
class LocationService {
    private final RestTemplate restTemplate = new RestTemplate();

    public String queryLocation(String serviceUrl) throws Exception {
        // Vulnerable URL handling with multiple protocol support
        URL url = new URL(serviceUrl);
        try (BufferedReader reader = new BufferedReader(
             new InputStreamReader(url.openStream()))) {
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line);
            }
            return response.toString();
        }
    }
}

// Security configuration with misleading validation
class URLValidator {
    private static final List<String> BLOCKED_PATHS = List.of(
        "metadata", "internal", "secret"
    );

    public static boolean isBlockedPath(String url) {
        return BLOCKED_PATHS.stream().anyMatch(url::contains);
    }
}
