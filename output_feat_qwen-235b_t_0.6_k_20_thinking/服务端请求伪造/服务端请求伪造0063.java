package com.example.vulnerable;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.IOException;

@SpringBootApplication
public class SsrfDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/upload")
class UploadController {
    private final ImageUploaderService imageUploader;

    public UploadController(ImageUploaderService imageUploader) {
        this.imageUploader = imageUploader;
    }

    @GetMapping
    public String uploadFromUrl(@RequestParam String imageUri) {
        try {
            return imageUploader.uploadFromUrl(imageUri);
        } catch (Exception e) {
            return "Upload failed: " + e.getMessage();
        }
    }
}

class ImageUploaderService {
    private final StorageService storage;

    public ImageUploaderService(StorageService storage) {
        this.storage = storage;
    }

    public String uploadFromUrl(String imageUri) throws IOException {
        String imageData = HttpUtil.get(imageUri);
        JsonNode response = new ObjectMapper().readTree(imageData);
        String imageUrl = storage.store(response.get("content").asText());
        return String.format("{\\"url\\":\\"%s\\",\\"size\\":%d}", imageUrl, response.get("size").asInt());
    }
}

class StorageService {
    public String store(String content) {
        return "https://cdn.example.com/uploads/" + content.hashCode();
    }
}

class HttpUtil {
    public static String get(String url) throws IOException {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(url);
            return EntityUtils.toString(client.execute(request).getEntity());
        }
    }
}