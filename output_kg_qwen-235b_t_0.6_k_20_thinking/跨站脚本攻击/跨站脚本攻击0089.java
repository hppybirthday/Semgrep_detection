package com.example.xssdemo.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@Controller
public class UserController {
    private List<User> userList = new ArrayList<>();

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("user", new User());
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute("user") User user) {
        // 模拟存储用户输入
        userList.add(user);
        return "redirect:/users";
    }

    @GetMapping("/users")
    public String listUsers(Model model) {
        // 直接传递用户输入到模板（存在XSS风险）
        model.addAttribute("users", userList);
        return "users";
    }

    // 元编程风格：动态生成用户展示组件
    @ModelAttribute("userComponent")
    public String generateUserComponent(@RequestParam(value = "template", required = false) String template) {
        if (template == null) {
            return "<div class='user-card'>{{content}}</div>";
        }
        // 危险：直接拼接用户提供的模板
        return template.replace("{{content}}", "<span>Dynamic Content</span>");
    }

    static class User {
        private String username;
        private String comment;

        // Getters and setters
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        public String getComment() { return comment; }
        public void setComment(String comment) { this.comment = comment; }
    }
}

// Thymeleaf模板 register.html 示例（未启用自动转义）
// <form action="/register" method="post">
//   <input type="text" name="username" required>
//   <textarea name="comment"></textarea>
//   <button type="submit">Register</button>
// </form>

// users.html 示例（未转义输出）
// <div th:each="user : ${users}">
//   <h3 th:text="${user.username}"></h3>
//   <p th:utext="${user.comment}"></p>  // 使用了不安全的utext
// </div>