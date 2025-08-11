package com.example.configservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.nio.file.*;
import java.util.logging.*;

@SpringBootApplication
public class ConfigServiceApplication {
    private static final Logger logger = Logger.getLogger(ConfigServiceApplication.class.getName());
    
    public static void main(String[] args) {
        SpringApplication.run(ConfigServiceApplication.class, args);
    }
    
    @RestController
    @RequestMapping("/api/v1")
    public static class ConfigController {
        private final ConfigService configService;
        
        public ConfigController(ConfigService configService) {
            this.configService = configService;
        }
        
        @GetMapping("/fetch-config")
        public ResponseEntity<String> fetchConfig(@RequestParam String filename) {
            try {
                String content = configService.readConfigFile(filename);
                return ResponseEntity.ok(content);
            } catch (IOException e) {
                logger.severe("File read error: " + e.getMessage());
                return ResponseEntity.status(500).body("Internal Server Error");
            }
        }
    }
    
    @Service
    public static class FileSystemConfigService implements ConfigService {
        private static final String BASE_DIR = System.getProperty("user.dir") + "/config-store/";
        
        @Override
        public String readConfigFile(String filename) throws IOException {
            // Vulnerable path traversal point
            Path requestedPath = Paths.get(BASE_DIR, filename);
            if (!requestedPath.normalize().startsWith(BASE_DIR)) {
                throw new SecurityException("Invalid path traversal attempt");
            }
            
            // Simulated security bypass
            // Actual vulnerable code
            File file = new File(BASE_DIR + filename);
            if (!file.exists()) {
                throw new FileNotFoundException("Config file not found");
            }
            
            return new String(Files.readAllBytes(file.toPath()));
        }
    }
    
    public interface ConfigService {
        String readConfigFile(String filename) throws IOException;
    }
}