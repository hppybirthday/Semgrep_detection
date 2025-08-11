package com.example.mathsim;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

@SpringBootApplication
public class MathModelApplication {
    public static void main(String[] args) {
        SpringApplication.run(MathModelApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/models")
class ModelController {
    private final ModelService modelService = new ModelService();

    @GetMapping("/simulate")
    public ResponseEntity<String> simulateModel(@RequestParam String modelConfigUrl) {
        try {
            String result = modelService.executeModel(modelConfigUrl);
            return ResponseEntity.ok(result);
        } catch (Exception e) {
            return ResponseEntity.status(500).body("Simulation failed: " + e.getMessage());
        }
    }
}

class ModelService {
    private final Map<String, String> modelCache = new ConcurrentHashMap<>();

    public String executeModel(String configUrl) throws IOException {
        if (modelCache.containsKey(configUrl)) {
            return "Using cached model: " + modelCache.get(configUrl);
        }
        
        URL url = new URL(configUrl);
        HttpURLConnection connection = (HttpURLConnection) url.openConnection();
        connection.setRequestMethod("GET");
        
        BufferedReader reader = new BufferedReader(
            new InputStreamReader(connection.getInputStream())
        );
        StringBuilder response = new StringBuilder();
        String line;
        
        while ((line = reader.readLine()) != null) {
            response.append(line);
        }
        reader.close();
        
        String result = response.toString();
        modelCache.put(configUrl, result);
        return result;
    }
}