package com.example.xssdemo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.config.annotation.ViewResolverRegistry;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;
import org.springframework.web.servlet.view.InternalResourceViewResolver;
import org.springframework.web.servlet.view.JstlView;

import java.util.HashMap;
import java.util.Map;

@RestController
@RequestMapping("/profile")
public class UserProfileController {
    @Autowired
    private UserService userService;

    @PostMapping("/update")
    public String updateProfile(@RequestParam String username, @RequestParam String bio) {
        userService.updateBio(username, bio);
        return generateProfilePage(username);
    }

    @GetMapping("/{username}")
    public String viewProfile(@PathVariable String username) {
        return generateProfilePage(username);
    }

    private String generateProfilePage(String username) {
        User user = userService.getUser(username);
        StringBuilder html = new StringBuilder();
        html.append("<html><body>");
        html.append("<h1>").append(user.getUsername()).append("'s Profile</h1>");
        html.append("<div style='border:1px solid #ccc;padding:10px;'>");
        html.append("<strong>Bio:</strong> ").append(user.getBio());  // 直接插入用户输入
        html.append("</div>");
        html.append("<br><a href='/'>Back to Home</a>");
        html.append("</body></html>");
        return html.toString();
    }
}

@Service
class UserService {
    private Map<String, User> userStore = new HashMap<>();

    public UserService() {
        userStore.put("admin", new User("admin", "System Administrator"));
    }

    public void updateBio(String username, String bio) {
        userStore.put(username, new User(username, bio));
    }

    public User getUser(String username) {
        return userStore.getOrDefault(username, new User("anonymous", "No profile available"));
    }
}

class User {
    private String username;
    private String bio;

    public User(String username, String bio) {
        this.username = username;
        this.bio = bio;
    }

    public String getUsername() { return username; }
    public String getBio() { return bio; }
}

@Configuration
@EnableWebMvc
class WebConfig implements WebMvcConfigurer {
    @Override
    public void configureViewResolvers(ViewResolverRegistry registry) {
        InternalResourceViewResolver resolver = new InternalResourceViewResolver();
        resolver.setPrefix("/views/");
        resolver.setSuffix(".jsp");
        resolver.setViewClass(JstlView.class);
        registry.viewResolver(resolver);
    }
}