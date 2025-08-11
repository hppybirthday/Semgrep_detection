package com.example.filedownload;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.*;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import javax.annotation.PostConstruct;
import java.net.*;
import java.io.*;
import java.util.*;

@RestController
@RequestMapping("/api/v1/files")
public class FileDownloadController {

    @Autowired
    private DownloadService downloadService;

    @GetMapping("/fetch")
    public ResponseEntity<String> fetchRemoteFile(@RequestParam String requestUri) {
        try {
            String fileContent = downloadService.processDownload(requestUri);
            return ResponseEntity.ok(fileContent);
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).body("Download failed");
        }
    }
}

@Service
class DownloadService {

    private final RestTemplate restTemplate;

    public DownloadService(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public String processDownload(String requestUri) throws Exception {
        String validatedUrl = sanitizeAndValidateUrl(requestUri);
        return executeDownload(validatedUrl);
    }

    private String sanitizeAndValidateUrl(String url) throws MalformedURLException {
        if (!url.startsWith("http://") && !url.startsWith("https://")) {
            url = "http://" + url;
        }

        URL parsedUrl = new URL(url);
        String host = parsedUrl.getHost();
        String path = parsedUrl.getPath();
        String protocol = parsedUrl.getProtocol();

        if (!isValidProtocol(protocol) || !isValidPath(path) || isBlockedHost(host)) {
            throw new SecurityException("URL validation failed");
        }

        return new URL(parsedUrl.getProtocol(), host, parsedUrl.getPort(), path).toString();
    }

    private boolean isValidProtocol(String protocol) {
        return "http".equals(protocol) || "https".equals(protocol);
    }

    private boolean isValidPath(String path) {
        return !path.contains("..") && path.startsWith("/files/");
    }

    private boolean isBlockedHost(String host) {
        try {
            InetAddress address = InetAddress.getByName(host);
            
            if (address.isLoopbackAddress()) {
                return true;
            }
            
            if (address.isSiteLocalAddress()) {
                return true;
            }
            
            byte[] ip = address.getAddress();
            if (ip[0] == 10) {
                return true;
            }
            
            return host.contains("metadata") || host.contains("docker") || host.contains("kubernetes");
            
        } catch (Exception e) {
            return false;
        }
    }

    private String executeDownload(String url) throws IOException {
        HttpHeaders headers = new HttpHeaders();
        headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));
        
        HttpEntity<String> entity = new HttpEntity<>(headers);
        
        ResponseEntity<String> response = restTemplate.exchange(
            url, HttpMethod.GET, entity, String.class);
        
        if (response.getStatusCode() != HttpStatus.OK) {
            throw new IOException("Download failed with status: " + response.getStatusCode());
        }
        
        return response.getBody();
    }
}

@Component
class SecurityMetadataConfig {
    private static final Set<String> SENSITIVE_PATHS = new HashSet<>(
        Arrays.asList("/internal/", "/admin/", "/api/private/"));

    public boolean isSensitivePath(String path) {
        return SENSITIVE_PATHS.stream().anyMatch(path::contains);
    }
}