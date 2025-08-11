package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestTemplate;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.URL;

@SpringBootApplication
public class SsrfDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }

    @RestController
    @RequestMapping("/api")
    public class ImageController {

        private final RestTemplate restTemplate;

        public ImageController(RestTemplate restTemplate) {
            this.restTemplate = restTemplate;
        }

        @GetMapping("/image")
        public String fetchImage(@RequestParam String url) {
            try {
                // 模拟获取图片元数据
                String response = restTemplate.getForObject(url, String.class);
                return "Image metadata: " + response.substring(0, Math.min(100, response.length())) + "...";
            } catch (Exception e) {
                return "Error fetching image: " + e.getMessage();
            }
        }

        // 模拟本地文件访问
        @GetMapping("/local")
        public String readLocalFile(@RequestParam String path) throws IOException {
            StringBuilder content = new StringBuilder();
            try (BufferedReader reader = new BufferedReader(
                    new InputStreamReader(new URL("file://" + path).openStream()))) {
                String line;
                while ((line = reader.readLine()) != null) {
                    content.append(line).append("\
");
                }
            }
            return content.toString();
        }
    }
}