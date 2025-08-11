package com.example.ml;

import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;

@RestController
@RequestMapping("/products")
public class ProductController {
    private final FileService fileService = new FileService();

    @PostMapping("/create")
    public String createProduct(@RequestParam String address) {
        try {
            String result = fileService.uploadFile(address);
            return "File processed, size: " + result.length();
        } catch (Exception e) {
            return "Error processing file";
        }
    }
}

class FileService {
    String uploadFile(String address) throws IOException {
        try (CloseableHttpClient client = HttpClients.createDefault()) {
            HttpPost request = new HttpPost(address);
            request.setHeader("Content-Type", "application/octet-stream");
            
            // Simulate file upload with metadata
            StringEntity entity = new StringEntity("Training data content");
            request.setEntity(entity);
            
            HttpResponse response = client.execute(request);
            return "Metadata: " + response.getStatusLine().toString();
        }
    }
}