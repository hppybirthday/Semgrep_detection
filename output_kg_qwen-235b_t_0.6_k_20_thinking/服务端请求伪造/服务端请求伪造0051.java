package com.example.taskmanager;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.util.EntityUtils;
import java.io.IOException;

@SpringBootApplication
@RestController
@RequestMapping("/tasks")
public class TaskManagerApplication {
    public static void main(String[] args) {
        SpringApplication.run(TaskManagerApplication.class, args);
    }

    @PostMapping("/{taskId}/status")
    public ResponseEntity<String> updateTaskStatus(@PathVariable String taskId, 
                                                   @RequestParam String status,
                                                   @RequestParam String webhookUrl) {
        try {
            // Simulate task status update logic
            System.out.println("Updating task " + taskId + " to status: " + status);
            
            // Vulnerable code: Blindly follow user-provided webhook URL
            if (webhookUrl != null && !webhookUrl.isEmpty()) {
                String response = HttpHelper.post(webhookUrl, "{'status': '" + status + "'}");
                System.out.println("Webhook response: " + response);
            }
            
            return new ResponseEntity<>("Task updated successfully", HttpStatus.OK);
        } catch (Exception e) {
            return new ResponseEntity<>("Error: " + e.getMessage(), HttpStatus.INTERNAL_SERVER_ERROR);
        }
    }
}

class HttpHelper {
    public static String post(String url, String body) throws IOException {
        try (CloseableHttpClient httpClient = HttpClients.createDefault()) {
            HttpPost request = new HttpPost(url);
            request.addHeader("Content-Type", "application/json");
            request.setEntity(new StringEntity(body));
            
            return EntityUtils.toString(httpClient.execute(request).getEntity());
        }
    }
}

// Task entity class
record Task(String id, String title, String description, String status) {}
