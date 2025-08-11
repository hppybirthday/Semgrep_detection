package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.logging.Logger;

@SpringBootApplication
public class PathTraversalDemo {
    private static final Logger logger = Logger.getLogger(PathTraversalDemo.class.getName());
    private static final String BASE_PATH = "/var/www/images/";

    public static void main(String[] args) {
        SpringApplication.run(PathTraversalDemo.class, args);
    }

    @RestController
    public static class ImageController {
        private final ImageService imageService = new ImageService();

        @GetMapping("/image/{viewName}")
        public ResponseEntity<byte[]> serveImage(@PathVariable String viewName) {
            try {
                byte[] imageContent = imageService.getImageContent(viewName);
                return ResponseEntity.ok().body(imageContent);
            } catch (IOException e) {
                logger.severe("Error accessing image: " + e.getMessage());
                return ResponseEntity.status(500).build();
            } catch (SecurityException e) {
                logger.warning("Security violation: " + e.getMessage());
                return ResponseEntity.status(403).build();
            }
        }
    }

    public static class ImageService {
        public byte[] getImageContent(String viewName) throws IOException {
            // Vulnerable path construction: assumes viewName is sanitized
            Path imagePath = Paths.get(BASE_PATH + viewName + ".jpg");
            
            // Defense illusion: basic existence check without path normalization
            if (!imagePath.toAbsolutePath().startsWith(BASE_PATH)) {
                throw new SecurityException("Invalid image path");
            }

            // Vulnerable file operation
            return Files.readAllBytes(imagePath);
        }
    }
}