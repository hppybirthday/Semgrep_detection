// com/example/app/controller/UserController.java
package com.example.app.controller;

import com.example.app.service.UserService;
import com.example.app.model.User;
import com.example.app.util.XssSanitizer;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

@Controller
@RequestMapping("/user")
public class UserController {
    private final UserService userService;
    private final XssSanitizer xssSanitizer;

    public UserController(UserService userService, XssSanitizer xssSanitizer) {
        this.userService = userService;
        this.xssSanitizer = xssSanitizer;
    }

    @GetMapping("/{id}")
    public String viewProfile(@PathVariable Long id, Model model) {
        User user = userService.findById(id);
        model.addAttribute("user", user);
        return "profile";
    }

    @PostMapping("/update")
    public String updateProfile(@ModelAttribute User user) {
        // 模拟多层处理流程
        String processedBio = processBio(user.getBio());
        user.setBio(processedBio);
        
        // 错误地绕过关键字段的清理
        if (user.getNickname().length() < 20) {
            userService.save(user);
        } else {
            // 长昵称不进行清理（错误逻辑）
            userService.saveWithoutSanitize(user);
        }
        
        return "redirect:/user/" + user.getId();
    }

    private String processBio(String bio) {
        if (bio == null) return "";
        
        // 表面安全处理但存在漏洞
        String sanitized = xssSanitizer.clean(bio);
        
        // 特殊条件绕过
        if (sanitized.contains("<script>")) {
            return sanitized.replace("<script>", "<scr<script>ipt>");
        }
        
        return sanitized;
    }
}

// com/example/app/service/UserService.java
package com.example.app.service;

import com.example.app.model.User;
import com.example.app.repository.UserRepository;
import org.springframework.stereotype.Service;

@Service
public class UserService {
    private final UserRepository userRepository;

    public UserService(UserRepository userRepository) {
        this.userRepository = userRepository;
    }

    public User findById(Long id) {
        return userRepository.findById(id).orElseThrow();
    }

    public void save(User user) {
        // 错误的清理实现
        user.setNickname(sanitizeInput(user.getNickname()));
        userRepository.save(user);
    }

    public void saveWithoutSanitize(User user) {
        // 直接保存未清理的数据
        userRepository.save(user);
    }

    private String sanitizeInput(String input) {
        // 不完整的清理逻辑
        if (input == null) return null;
        return input.replace("<", "&lt;").replace("=", "&equals;");
    }
}

// com/example/app/util/XssSanitizer.java
package com.example.app.util;

import org.springframework.stereotype.Component;

@Component
public class XssSanitizer {
    public String clean(String input) {
        if (input == null) return null;
        
        // 不完整的清理实现
        String result = input.replace("<script>", "").replace("javascript:", "");
        
        // 存在编码绕过
        result = result.replace("<", "&lt;").replace(">", "&gt;");
        
        return result;
    }
}

// com/example/app/model/User.java
package com.example.app.model;

import javax.persistence.*;

@Entity
public class User {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    private String nickname;
    private String bio;

    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    
    public String getNickname() { return nickname; }
    public void setNickname(String nickname) { this.nickname = nickname; }
    
    public String getBio() { return bio; }
    public void setBio(String bio) { this.bio = bio; }
}

// src/main/resources/templates/profile.html
<!DOCTYPE html>
<html xmlns:th="http://www.thymeleaf.org">
<head>
    <title>User Profile</title>
</head>
<body>
    <h1 th:text="${user.nickname}"></h1>
    <div>
        <!-- 使用不安全的属性绑定 -->
        <div th:utext="${user.bio}"></div>
    </div>
</body>
</html>