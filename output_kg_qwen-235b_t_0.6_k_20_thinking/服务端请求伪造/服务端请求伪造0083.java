package com.example.ssrfdemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.client.RestClientException;
import org.springframework.web.client.RestTemplate;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.logging.Logger;

@SpringBootApplication
public class SsrfDemoApplication {

    public static void main(String[] args) {
        SpringApplication.run(SsrfDemoApplication.class, args);
    }

    @Bean
    public RestTemplate restTemplate() {
        return new RestTemplate();
    }
}

@Controller
class ImageProxyController {

    private static final Logger logger = java.util.logging.Logger.getLogger(ImageProxyController.class.getName());

    @Autowired
    private RestTemplate restTemplate;

    @GetMapping("/image")
    public void getImage(@RequestParam String url, HttpServletResponse response) throws IOException {
        try {
            // 漏洞点：仅检查协议，未验证主机和路径
            if (!isValidUrl(url)) {
                throw new IllegalArgumentException("Invalid URL protocol");
            }
            byte[] imageBytes = restTemplate.getForObject(url, byte[].class);
            response.setContentType("image/jpeg");
            response.getOutputStream().write(imageBytes);
        } catch (RestClientException e) {
            logger.severe("Error fetching image from URL: " + e.getMessage());
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Error fetching image");
        }
    }

    // 不充分的URL验证
    private boolean isValidUrl(String url) {
        return url.startsWith("http://") || url.startsWith("https://");
    }
}