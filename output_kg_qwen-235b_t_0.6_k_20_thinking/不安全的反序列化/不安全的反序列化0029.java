package com.example.vulnerablemicroservice;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.util.Base64;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class DeserializationVulnApp {

    public static void main(String[] args) {
        SpringApplication.run(DeserializationVulnApp.class, args);
    }

    @PostMapping("/process")
    public String processUserInput(@RequestParam String payload) {
        try {
            byte[] decoded = Base64.getDecoder().decode(payload);
            try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decoded))) {
                Object obj = ois.readObject();
                return "Processed: " + obj.getClass().getName();
            }
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    @Bean
    public UserDetailsService userDetailsService() {
        return new UserDetailsService();
    }

    static class User implements Serializable {
        private String username;
        private transient String sensitiveData;

        public User(String username) {
            this.username = username;
            this.sensitiveData = "internal_secret";
        }

        private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
            ois.defaultReadObject();
            sensitiveData = "internal_secret";
        }

        public String toString() {
            return "User{username='" + username + "'}";
        }
    }

    static class UserDetailsService {
        public void saveUser(User user) {
            // Simulated storage
        }
    }

    @GetMapping("/health")
    public String healthCheck() {
        return "OK";
    }
}

// Attack surface:
// 1. /api/process endpoint accepts Base64 serialized objects
// 2. Direct use of ObjectInputStream without validation
// 3. Potential for RCE through gadget chains
// 4. Exposes full Java deserialization attack surface
// 5. Cloud-native deployment increases exposure surface