package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.ModelAndView;
import javax.persistence.*;
import java.util.List;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

@Entity
class UserProfile {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    private String username;
    private String displayName; // Vulnerable field
    
    // Getters/Setters
}

interface UserProfileRepository extends JpaRepository<UserProfile, Long> {}

@Service
class ProfileService {
    private final UserProfileRepository repo;

    public ProfileService(UserProfileRepository repo) {
        this.repo = repo;
    }

    public void saveProfile(UserProfile profile) {
        // Vulnerable: Only basic sanitization
        profile.setDisplayName(profile.getDisplayName().replaceAll("<script>", ""));
        repo.save(profile);
    }

    public List<UserProfile> getAllProfiles() {
        return repo.findAll();
    }
}

@RestController
@RequestMapping("/profiles")
class ProfileController {
    private final ProfileService service;

    public ProfileController(ProfileService service) {
        this.service = service;
    }

    @GetMapping
    public ModelAndView listProfiles() {
        ModelAndView mv = new ModelAndView("profiles");
        mv.addObject("profiles", service.getAllProfiles());
        return mv;
    }

    @PostMapping
    public String createProfile(@RequestParam String username, 
                              @RequestParam String displayName) {
        UserProfile profile = new UserProfile();
        profile.setUsername(username);
        profile.setDisplayName(displayName);
        service.saveProfile(profile);
        return "redirect:/profiles";
    }
}

// Thymeleaf template (resources/templates/profiles.html)
// Vulnerable: Uses unsafe text output
/*
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head><title>Profiles</title></head>
<body>
    <h1>User Profiles</h1>
    <div th:each="profile : ${profiles}">
        <p><strong>Username:</strong> <span th:text="${profile.username}"></span></p>
        <p><strong>Display Name:</strong> <span th:utext="${profile.displayName}"></span></p> <!-- XSS Vulnerability -->
    </div>
</body>
</html>
*/