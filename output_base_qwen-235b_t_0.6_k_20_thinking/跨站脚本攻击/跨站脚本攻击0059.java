package com.bank.demo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class AccountController {
    private UserService userService = new UserService();

    @GetMapping("/profile")
    public String showProfileForm(Model model) {
        model.addAttribute("user", new User("John Doe", "123 Main St"));
        return "profile";
    }

    @PostMapping("/profile")
    public String updateProfile(
            @RequestParam("name") String name,
            @RequestParam("address") String address,
            Model model) {
        User user = userService.updateProfile(name, address);
        model.addAttribute("user", user);
        return "profile";
    }
}

class User {
    private String name;
    private String address;

    public User(String name, String address) {
        this.name = name;
        this.address = address;
    }

    public String getName() { return name; }
    public String getAddress() { return address; }
}

class UserService {
    public User updateProfile(String name, String address) {
        // 模拟持久化操作
        System.out.println("Updating profile: " + name + ", " + address);
        return new User(name, address);
    }
}

// Thymeleaf模板(profile.html):
// <!DOCTYPE html>
// <html xmlns:th="http://www.thymeleaf.org">
// <body>
// <h2>User Profile</h2>
// <form action="/profile" method="post">
//   Name: <input type="text" name="name" th:value="${user.name}"><br>
//   Address: <input type="text" name="address" th:value="${user.address}"><br>
//   <input type="submit" value="Update">
// </form>
// <div th:text="'Welcome, ' + ${user.name}"></div>
// <div th:text="'Address: ' + ${user.address}"></div>
// </body>
// </html>