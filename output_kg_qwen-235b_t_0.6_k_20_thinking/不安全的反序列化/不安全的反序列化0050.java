package com.example.vulnerableapp;

import org.springframework.web.bind.annotation.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/user")
public class UserController {
    private static final Logger logger = LoggerFactory.getLogger(UserController.class);

    @PostMapping("/profile")
    public String updateUserProfile(@RequestParam("data") String base64Data) {
        try {
            byte[] decodedBytes = Base64.getDecoder().decode(base64Data);
            ByteArrayInputStream bais = new ByteArrayInputStream(decodedBytes);
            ObjectInputStream ois = new ObjectInputStream(bais);
            UserProfile profile = (UserProfile) ois.readObject();
            ois.close();
            
            // Simulate processing
            logger.info("Processing profile for user: {}", profile.getUsername());
            return String.format("Profile updated for %s with preferences: %s", 
                profile.getUsername(), profile.getPreferences());
        } catch (Exception e) {
            logger.error("Deserialization error: {}", e.getMessage());
            return "Invalid profile data";
        }
    }

    @GetMapping("/demo")
    public String demoUsage() {
        return "Send POST request to /user/profile with base64-encoded serialized UserProfile object";
    }
}

class UserProfile implements Serializable {
    private String username;
    private transient Map<String, String> preferences;
    
    public UserProfile(String username, Map<String, String> preferences) {
        this.username = username;
        this.preferences = preferences;
    }

    // Getters and setters
    public String getUsername() { return username; }
    public Map<String, String> getPreferences() { return preferences; }
    
    @Override
    public String toString() {
        return String.format("{username: '%s', preferences: %s}", username, preferences);
    }
}