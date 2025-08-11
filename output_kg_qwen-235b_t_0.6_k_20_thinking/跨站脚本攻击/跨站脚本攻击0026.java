package com.bank.app.controller;

import com.bank.app.domain.User;
import com.bank.app.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@Controller
@RequestMapping("/user")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/profile")
    public String viewProfile(@RequestParam String username, Model model) {
        User user = userService.findByUsername(username);
        model.addAttribute("user", user);
        return "profile";
    }

    @PostMapping("/update")
    public String updateProfile(@RequestParam String username, 
                               @RequestParam String bio, 
                               Model model) {
        User user = userService.findByUsername(username);
        user.setBio(bio);
        userService.save(user);
        model.addAttribute("success", "Profile updated successfully");
        return "profile";
    }
}

package com.bank.app.service;

import com.bank.app.domain.User;
import org.springframework.stereotype.Service;

import java.util.HashMap;
import java.util.Map;

@Service
public class UserService {
    private Map<String, User> userStore = new HashMap<>();

    public UserService() {
        userStore.put("alice", new User("alice", "Alice Smith", ""));
        userStore.put("bob", new User("bob", "Bob Johnson", ""));
    }

    public User findByUsername(String username) {
        return userStore.get(username);
    }

    public void save(User user) {
        userStore.put(user.getUsername(), user);
    }
}

package com.bank.app.domain;

public class User {
    private String username;
    private String fullName;
    private String bio;

    public User(String username, String fullName, String bio) {
        this.username = username;
        this.fullName = fullName;
        this.bio = bio;
    }

    public String getUsername() {
        return username;
    }

    public String getFullName() {
        return fullName;
    }

    public String getBio() {
        return bio;
    }

    public void setBio(String bio) {
        this.bio = bio;
    }
}

// profile.html
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <head><title>User Profile</title></head>
// <body>
//     <h1 th:text="${user.fullName}"></h1>
//     <div th:utext="${user.bio}"></div>  <!-- Vulnerable line -->
//     <form th:action="@{/user/update}" method="post">
//         <input type="hidden" name="username" th:value="${user.username}"/>
//         <textarea name="bio" rows="4" cols="50">th:text="${user.bio}"</textarea>
//         <input type="submit" value="Update Profile"/>
//     </form>
//     <div th:if="${success}" th:text="${success}"></div>
// </body>
// </html>