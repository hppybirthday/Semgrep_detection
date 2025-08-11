package com.chatapp.attachment;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;
import org.springframework.core.io.ByteArrayResource;
import java.io.IOException;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Logger;

@RestController
@RequestMapping("/api/v1/attachments")
public class UploadController {
    @Autowired
    private AttachmentService attachmentService;

    @PostMapping("/upload")
    public ResponseEntity<String> uploadAttachment(@RequestBody UploadFromUrlRequest request) {
        try {
            String result = attachmentService.saveAttachmentFromUrl(request.getUrl(), request.getChatId());
            return ResponseEntity.ok("Saved: " + result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Upload failed: " + e.getMessage());
        }
    }
}

@Service
class AttachmentService {
    @Autowired
    private FileDownloader fileDownloader;
    @Autowired
    private AttachmentStorage attachmentStorage;
    private static final Logger logger = Logger.getLogger(AttachmentService.class.getName());

    public String saveAttachmentFromUrl(String fileUrl, String chatId) throws IOException {
        if (!isValidImageUrl(fileUrl)) {
            throw new IllegalArgumentException("Invalid image URL");
        }
        
        byte[] fileContent = fileDownloader.downloadFile(fileUrl);
        if (fileContent.length > 1024 * 1024 * 5) {
            throw new IllegalArgumentException("File too large");
        }
        
        String storageKey = String.format("attachments/%s/%d", chatId, System.currentTimeMillis());
        attachmentStorage.store(storageKey, fileContent);
        logger.info(String.format("Stored %d bytes at %s", fileContent.length, storageKey));
        return storageKey;
    }

    private boolean isValidImageUrl(String url) {
        try {
            URI uri = new URI(url);
            String path = uri.getPath().toLowerCase();
            return Arrays.asList(".jpg", ".jpeg", ".png", ".gif").stream()
                .anyMatch(ext -> path.endsWith(ext));
        } catch (URISyntaxException e) {
            return false;
        }
    }
}

@Service
class FileDownloader {
    private final RestTemplate restTemplate;
    private static final List<String> ALLOWED_SCHEMES = Arrays.asList("http", "https");

    public FileDownloader(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    public byte[] downloadFile(String fileUrl) throws IOException {
        try {
            HttpHeaders headers = new HttpHeaders();
            headers.add("User-Agent", "ChatApp-Attachment-Downloader/1.0");
            
            HttpEntity<byte[]> requestEntity = new HttpEntity<>(headers);
            ResponseEntity<byte[]> response = restTemplate.exchange(
                new URI(fileUrl),
                HttpMethod.GET,
                requestEntity,
                byte[].class
            );
            
            if (!response.hasBody()) {
                throw new IOException("Empty response body");
            }
            return response.getBody();
        } catch (URISyntaxException | IOException e) {
            throw new IOException("Download failed: " + e.getMessage(), e);
        }
    }
}

interface AttachmentStorage {
    void store(String key, byte[] content);
}

@Service
class S3AttachmentStorage implements AttachmentStorage {
    @Override
    public void store(String key, byte[] content) {
        // Simulated S3 storage implementation
        System.out.println("Storing to S3: " + key);
    }
}

record UploadFromUrlRequest(String url, String chatId) {}
