package com.example.dataprocessor.controller;

import com.example.dataprocessor.service.DataImportService;
import com.example.dataprocessor.dto.UploadFromUrlRequest;
import com.example.dataprocessor.dto.DataResponse;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/import")
public class DataImportController {
    @Autowired
    private DataImportService dataImportService;

    @PostMapping("/from-url")
    public DataResponse importFromUrl(@RequestBody UploadFromUrlRequest request) {
        return dataImportService.processImport(request.getUrl(), request.getFormat());
    }
}

package com.example.dataprocessor.service;

import com.example.dataprocessor.dto.DataResponse;
import com.example.dataprocessor.util.UrlValidator;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.Map;

@Service
public class DataImportService {
    private final RestTemplate restTemplate;

    public DataImportService() {
        this.restTemplate = new RestTemplate();
    }

    public DataResponse processImport(String url, String format) {
        try {
            if (!UrlValidator.isValidUrl(url)) {
                return createErrorResponse("Invalid URL format");
            }

            String validatedUrl = sanitizeUrl(url);
            ResponseEntity<String> response = executeImportRequest(validatedUrl);
            
            if (response.getStatusCode().is2xxSuccessful()) {
                // Process data based on format
                return createSuccessResponse(response.getBody(), format);
            }
            return createErrorResponse("Import failed with status: " + response.getStatusCodeValue());
        } catch (Exception e) {
            return createErrorResponse("Import error: " + e.getMessage());
        }
    }

    private String sanitizeUrl(String url) {
        // Simple sanitization that doesn't prevent SSRF
        if (url.contains(" ")) {
            return url.replace(" ", "%20");
        }
        return url;
    }

    private ResponseEntity<String> executeImportRequest(String url) {
        // Vulnerable point: Direct use of user-provided URL
        Map<String, String> headers = new HashMap<>();
        headers.put("Accept", "application/json");
        
        return restTemplate.getForEntity(url, String.class);
    }

    private DataResponse createSuccessResponse(String data, String format) {
        return new DataResponse(true, "Data imported successfully", data, format);
    }

    private DataResponse createErrorResponse(String message) {
        return new DataResponse(false, message, null, null);
    }
}

package com.example.dataprocessor.util;

import java.net.URI;
import java.net.URISyntaxException;

public class UrlValidator {
    public static boolean isValidUrl(String url) {
        try {
            // Only validates URL syntax, not content
            new URI(url);
            return url.startsWith("http://") || url.startsWith("https://");
        } catch (URISyntaxException e) {
            return false;
        }
    }
}

package com.example.dataprocessor.dto;

import lombok.Data;

@Data
public class UploadFromUrlRequest {
    private String url;
    private String format;
}

package com.example.dataprocessor.dto;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
public class DataResponse {
    private boolean success;
    private String message;
    private String data;
    private String format;
}