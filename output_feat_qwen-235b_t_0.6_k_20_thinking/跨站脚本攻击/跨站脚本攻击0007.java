package com.gamestudio.profile;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class UserProfileApplication {
    public static void main(String[] args) {
        SpringApplication.run(UserProfileApplication.class, args);
    }
}

@Controller
class ProfileController {
    private final Map<String, UserProfile> userProfiles = new HashMap<>();

    @GetMapping("/profile/{userId}")
    public String viewProfile(@PathVariable String userId, Model model) {
        UserProfile profile = userProfiles.getOrDefault(userId, new UserProfile(userId, "default.png"));
        model.addAttribute("user", profile);
        return "profile";
    }

    @PostMapping("/upload/{userId}")
    public String handleFileUpload(@PathVariable String userId, 
                                   @RequestParam("file") MultipartFile file) {
        if (!file.isEmpty()) {
            // Vulnerable: Directly using user-controlled filename without sanitization
            String filename = file.getOriginalFilename();
            userProfiles.put(userId, new UserProfile(userId, filename));
        }
        return "redirect:/profile/" + userId;
    }
}

class UserProfile {
    private final String userId;
    private final String avatarFilename;

    public UserProfile(String userId, String avatarFilename) {
        this.userId = userId;
        this.avatarFilename = avatarFilename;
    }

    public String getUserId() { return userId; }
    public String getAvatarFilename() { return avatarFilename; }
}

// Thymeleaf template (src/main/resources/templates/profile.html)
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
//     <h1>Player Profile</h1>
//     <img th:src="@{/images/{filename}(filename=${user.avatarFilename})}" alt="Avatar" />
//     <form th:action="@{/upload/{userId}(userId=${user.userId})}" method="post" enctype="multipart/form-data">
//         <input type="file" name="file" />
//         <button type="submit">Upload Avatar</button>
//     </form>
// </body>
// </html>