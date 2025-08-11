package com.example.ml;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URL;

@SpringBootApplication
public class MlApp {
    public static void main(String[] args) {
        SpringApplication.run(MlApp.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@RestController
class ModelController {
    private final RestTemplate restTemplate;

    public ModelController(RestTemplate restTemplate) {
        this.restTemplate = restTemplate;
    }

    @GetMapping("/load")
    public String loadModel(@RequestParam String modelUrl) {
        try {
            // 漏洞点：直接使用用户输入的URL
            String modelData = restTemplate.getForObject(new URL(modelUrl).toString(), String.class);
            return "Model loaded: " + modelData.substring(0, Math.min(20, modelData.length())) + "...";
        } catch (Exception e) {
            return "Error loading model: " + e.getMessage();
        }
    }

    @GetMapping("/train")
    public String trainModel(@RequestParam String datasetUrl) {
        try {
            // SSRF攻击面：内部网络探测
            URL url = new URL(datasetUrl);
            BufferedReader reader = new BufferedReader(
                new InputStreamReader(url.openStream()));
            String line = reader.readLine();
            return "Training with data: " + (line != null ? line : "empty");
        } catch (Exception e) {
            return "Training failed: " + e.getMessage();
        }
    }
}