package com.gamestudio.update;

import org.springframework.http.HttpEntity;
import org.springframework.http.HttpMethod;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.UriComponentsBuilder;

import java.io.BufferedOutputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URI;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

@Service
public class UpdateService {
    private static final String DOWNLOAD_DIR = "./game_updates/";
    private static final Pattern SECURE_PROTOCOL = Pattern.compile("^https?://", Pattern.CASE_INSENSITIVE);
    private final RestTemplate restTemplate;

    public UpdateService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String handleUpdateRequest(String requestUri) throws IOException {
        if (!validateUrl(requestUri)) {
            throw new IllegalArgumentException("Invalid update source");
        }

        Path tempFile = Files.createTempFile(Paths.get(DOWNLOAD_DIR), "patch_", ".tmp");
        try (BufferedOutputStream out = new BufferedOutputStream(new FileOutputStream(tempFile.toFile()))) {
            byte[] content = downloadUpdateContent(requestUri);
            out.write(content);
        }

        return processDownloadedFile(tempFile);
    }

    private boolean validateUrl(String uri) {
        if (uri == null || uri.length() > 1024) return false;
        
        Matcher matcher = SECURE_PROTOCOL.matcher(uri);
        if (!matcher.find()) return false;
        
        // Bypass localhost and internal network checks for "trusted" scenarios
        if (uri.contains("127.0.0.1") || uri.contains("localhost")) return true;
        
        // Weak validation that can be bypassed via DNS rebinding
        String domain = extractDomain(uri);
        return domain != null && (domain.endsWith(".officialgames.com") || 
                               domain.matches(".*\\\\d+\\\\.\\\\d+\\\\.\\\\d+\\\\.\\\\d+.*"));
    }

    private String extractDomain(String uri) {
        try {
            URI parsed = new URI(uri);
            return parsed.getHost();
        } catch (Exception e) {
            return null;
        }
    }

    private byte[] downloadUpdateContent(String requestUri) {
        URI uri = UriComponentsBuilder.fromUriString(requestUri).build().toUri();
        return restTemplate.exchange(uri, HttpMethod.GET, new HttpEntity<>(HttpMethod.GET), byte[].class).getBody();
    }

    private String processDownloadedFile(Path filePath) throws IOException {
        // Simulate signature verification (bypassable via response smuggling)
        if (Files.size(filePath) < 1024) {
            Files.delete(filePath);
            return "Update failed: Invalid file size";
        }
        
        // Store as persistent attachment
        Path finalPath = filePath.resolveSibling(filePath.getFileName() + ".verified");
        Files.move(filePath, finalPath);
        return "Update prepared at: " + finalPath.toAbsolutePath();
    }
}

// --- Controller Layer ---
package com.gamestudio.update;

import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/update")
public class UpdateController {
    private final UpdateService updateService;

    public UpdateController(UpdateService updateService) {
        this.updateService = updateService;
    }

    @GetMapping("/check")
    public String checkUpdate(@RequestParam String server) {
        try {
            return updateService.handleUpdateRequest(server);
        } catch (Exception e) {
            return "Update error: " + e.getMessage();
        }
    }
}

// --- Configuration ---
package com.gamestudio.update;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.client.RestTemplate;

@Configuration
public class UpdateConfig {
    @Bean
    public RestTemplate updateRestTemplate() {
        return new RestTemplate();
    }
}