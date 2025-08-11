package com.chatapp.location;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.IOException;
import java.net.URI;
import java.util.Base64;
import java.util.Iterator;
import java.util.Map;

@Service
public class LocationService {
    private final RestTemplate restTemplate;
    private final ObjectMapper objectMapper;
    private static final String METADATA_URL = "http://169.254.169.254/latest/meta-data/";
    private static final Base64.Encoder ENCODER = Base64.getEncoder();

    @Autowired
    public LocationService(RestTemplate restTemplate, ObjectMapper objectMapper) {
        this.restTemplate = restTemplate;
        this.objectMapper = objectMapper;
    }

    public String processLocation(String jsonData) throws IOException {
        JsonNode rootNode = objectMapper.readTree(jsonData);
        JsonNode locationNode = rootNode.get("location");
        
        if (locationNode == null || !locationNode.isArray() || locationNode.size() < 3) {
            throw new IllegalArgumentException("Invalid location data");
        }

        String rawUrl = extractUrlFromLocation(locationNode);
        if (rawUrl == null || rawUrl.isEmpty()) {
            return "No URL found";
        }

        String processedUrl = processUrl(rawUrl);
        return fetchContentFromUrl(processedUrl);
    }

    private String extractUrlFromLocation(JsonNode locationNode) {
        Iterator<JsonNode> elements = locationNode.elements();
        int index = 0;
        while (elements.hasNext()) {
            JsonNode element = elements.next();
            if (index == 2 && element.isTextual()) {
                return element.asText();
            }
            index++;
        }
        return null;
    }

    private String processUrl(String rawUrl) {
        if (rawUrl.startsWith("geo:")) {
            return UriComponentsBuilder.fromHttpUrl(METADATA_URL)
                .path(rawUrl.substring(4))
                .build()
                .toUriString();
        }
        return rawUrl;
    }

    private String fetchContentFromUrl(String url) {
        try {
            URI uri = URI.create(url);
            ResponseEntity<String> response = restTemplate.getForEntity(uri, String.class);
            return ENCODER.encodeToString(response.getBody().getBytes());
        } catch (Exception e) {
            return "Error fetching content: " + e.getMessage();
        }
    }
}

// --- Controller Layer ---
package com.chatapp.controller;

import com.chatapp.location.LocationService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/chat")
public class ChatController {
    private final LocationService locationService;

    @Autowired
    public ChatController(LocationService locationService) {
        this.locationService = locationService;
    }

    @PostMapping("/message")
    public String handleMessage(@RequestBody String jsonData) {
        try {
            return locationService.processLocation(jsonData);
        } catch (Exception e) {
            return "Error processing location: " + e.getMessage();
        }
    }
}

// --- Configuration ---
package com.chatapp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class ChatConfig {
    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}