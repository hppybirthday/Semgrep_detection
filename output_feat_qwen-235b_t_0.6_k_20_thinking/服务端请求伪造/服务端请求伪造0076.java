package com.crm.example;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.io.IOException;

@SpringBootApplication
public class CrmApplication {
    public static void main(String[] args) {
        SpringApplication.run(CrmApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/import")
class DataImportController {
    private final AttachmentService attachmentService;

    public DataImportController(AttachmentService attachmentService) {
        this.attachmentService = attachmentService;
    }

    @PostMapping("/json")
    public ResponseEntity<String> importFromJson(@RequestParam String endPoint, @RequestParam String variableEndPoint) {
        try {
            // 模拟从JSON数据中解析出URL参数
            String url = "http://api.example.com/data?endpoint=" + endPoint + "&var=" + variableEndPoint;
            
            if (attachmentService.uploadFromUrl(url)) {
                return ResponseEntity.ok("Import successful");
            }
            return ResponseEntity.status(500).body("Import failed");
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Server error");
        }
    }
}

class AttachmentService {
    boolean uploadFromUrl(String targetUrl) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpGet request = new HttpGet(targetUrl);
            try (CloseableHttpResponse response = httpClient.execute(request)) {
                // 仅验证连接状态，不处理响应内容
                return response.getStatusLine().getStatusCode() == 200;
            }
        }
    }
}