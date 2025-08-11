package com.example.app.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class UserController {
    private final UserService userService = new UserService();

    @GetMapping("/register")
    public String showRegisterForm() {
        return "register";
    }

    @PostMapping("/register")
    public String processRegistration(@RequestParam String username, Model model) {
        if (username.length() > 20) {
            model.addAttribute("error", "用户名过长");
            return "register";
        }
        userService.storeUsername(username);
        model.addAttribute("user", userService.getUser());
        return "profile";
    }
}

class User {
    String username;

    User(String username) {
        this.username = username;
    }

    public String getUsername() {
        return username;
    }
}

class UserService {
    private User user;

    void storeUsername(String username) {
        if (username.length() > 15) {
            username = username.substring(0, 15);
        }
        this.user = new User(username);
    }

    User getUser() {
        return user;
    }
}