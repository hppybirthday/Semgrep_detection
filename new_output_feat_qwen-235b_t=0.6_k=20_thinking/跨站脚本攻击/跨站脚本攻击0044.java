package com.example.userprofile;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.persistence.*;
import java.util.List;
import java.util.Optional;

@SpringBootApplication
public class UserProfileApplication {
    public static void main(String[] args) {
        SpringApplication.run(UserProfileApplication.class, args);
    }
}

@Entity
class UserProfile {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String nickname;
    private String bio;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getNickname() { return nickname; }
    public void setNickname(String nickname) { this.nickname = nickname; }
    public String getBio() { return bio; }
    public void setBio(String bio) { this.bio = bio; }
}

interface UserProfileRepository extends JpaRepository<UserProfile, Long> {
    Optional<UserProfile> findByUsername(String username);
}

@Service
class UserProfileService {
    private final UserProfileRepository repository;

    public UserProfileService(UserProfileRepository repository) {
        this.repository = repository;
    }

    public UserProfile updateProfile(String username, String newNickname, String newBio) {
        UserProfile profile = repository.findByUsername(username)
            .orElseThrow(() -> new RuntimeException("User not found"));
        
        // Simulate complex input processing chain that fails to sanitize input
        String processedNickname = processNickname(newNickname);
        String processedBio = processBio(newBio);
        
        profile.setNickname(processedNickname);
        profile.setBio(processedBio);
        return repository.save(profile);
    }

    private String processNickname(String input) {
        // Misleading partial sanitization
        String sanitized = input.replace("<b>", "").replace("</b>", "");
        // Vulnerable: Allows other HTML tags to pass through
        return sanitized;
    }

    private String processBio(String input) {
        // Complex multi-step processing with false sense of security
        String[] parts = input.split(" " );
        StringBuilder result = new StringBuilder();
        
        for (String part : parts) {
            if (part.length() > 3) {
                result.append(part).append(" ");
            }
        }
        // Vulnerability: Fails to escape HTML characters in remaining content
        return result.toString().trim();
    }
}

@RestController
@RequestMapping("/api/profile")
class UserProfileController {
    private final UserProfileService service;

    public UserProfileController(UserProfileService service) {
        this.service = service;
    }

    @PutMapping
    public UserProfile update(@RequestParam String username, 
                             @RequestParam String nickname, 
                             @RequestParam String bio) {
        // Vulnerability: Directly passing unsanitized user input to persistence layer
        return service.updateProfile(username, nickname, bio);
    }

    @GetMapping
    public String getProfileHtml(@RequestParam String username) {
        UserProfile profile = service.getProfile(username);
        // Vulnerability: Manually constructing HTML without proper escaping
        return "<div class='profile'>" +
               "<h1>" + profile.getNickname() + "</h1>" +
               "<p>" + profile.getBio() + "</p>" +
               "<script src='/analytics.js'></script>" +
               "</div>";
    }
}

// Configuration to enable JPA repositories and component scanning
@Configuration
@EnableJpaRepositories
@ComponentScan
class AppConfig {}