package com.example.app.controller;

import com.example.app.service.UserService;
import com.example.app.model.User;
import com.example.app.util.TemplateRenderer;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;

@Controller
@RequestMapping("/profile")
public class UserProfileController {
    @Autowired
    private UserService userService;
    @Autowired
    private TemplateRenderer templateRenderer;

    @PostMapping("/update")
    @ResponseBody
    public String updateProfile(@RequestBody User user, HttpServletResponse response) {
        if (userService.updateUserProfile(user)) {
            try {
                return templateRenderer.renderUserBio(user.getId());
            } catch (IOException e) {
                response.setStatus(500);
                return "Internal Server Error";
            }
        }
        response.setStatus(400);
        return "Invalid input";
    }
}

package com.example.app.service;

import com.example.app.model.User;
import com.example.app.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import com.example.app.util.XssValidator;

@Service
public class UserService {
    @Autowired
    private UserRepository userRepository;

    public boolean updateUserProfile(User user) {
        if (user == null || user.getId() == null || user.getId() <= 0) {
            return false;
        }
        
        // 模拟对其他字段的安全处理
        if (user.getEmail() != null && !XssValidator.isValidEmail(user.getEmail())) {
            return false;
        }
        
        // 漏洞点：未对bio字段进行XSS过滤
        userRepository.saveUser(user);
        return true;
    }
}

package com.example.app.util;

import com.example.app.model.User;
import com.example.app.repository.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
public class TemplateRenderer {
    @Autowired
    private UserRepository userRepository;

    public String renderUserBio(Long userId) throws IOException {
        User user = userRepository.getUserById(userId);
        if (user == null) {
            throw new IOException("User not found");
        }
        
        // 模拟模板渲染过程
        StringBuilder html = new StringBuilder();
        html.append("<div class='profile'>\
");
        html.append("  <h2>").append(user.getUsername()).append("</h2>\
");
        html.append("  <div class='bio'>\
");
        html.append("    <script>\
");
        // 漏洞触发点：直接插入未经处理的用户输入
        html.append("      var bioData = '").append(user.getBio()).append("';\
");
        html.append("      document.write(bioData);\
");
        html.append("    </script>\
");
        html.append("  </div>\
");
        html.append("</div>");
        
        return html.toString();
    }
}

package com.example.app.util;

public class XssValidator {
    // 模拟安全检查的误导性代码
    public static boolean isValidEmail(String email) {
        return email != null && email.matches("[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}");
    }
}

package com.example.app.repository;

import com.example.app.model.User;
import org.springframework.stereotype.Repository;

import java.util.HashMap;
import java.util.Map;

@Repository
public class UserRepository {
    private final Map<Long, User> userStorage = new HashMap<>();

    public void saveUser(User user) {
        if (user != null && user.getId() != null) {
            userStorage.put(user.getId(), user);
        }
    }

    public User getUserById(Long userId) {
        return userId != null ? userStorage.get(userId) : null;
    }
}

package com.example.app.model;

public class User {
    private Long id;
    private String username;
    private String email;
    private String bio;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
    
    public String getBio() { return bio; }
    public void setBio(String bio) { this.bio = bio; }
}