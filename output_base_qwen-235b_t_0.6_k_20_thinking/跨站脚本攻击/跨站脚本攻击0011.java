package com.example.bank.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;

@Controller
public class UserController {
    private String errorMessage = "";

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("error", errorMessage);
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@RequestParam String username, @RequestParam String password) {
        if (username == null || username.isEmpty() || password == null || password.isEmpty()) {
            errorMessage = "Username or password cannot be empty";
            return "redirect:/register";
        }
        
        if (username.contains("<") || username.contains("script")) {
            // 模拟安全检查失败
            errorMessage = "Invalid username detected: " + username;
            return "redirect:/register";
        }
        
        // 模拟数据库持久化失败
        if (password.length() < 8) {
            errorMessage = "Password too short for user: " + username;
            return "redirect:/register";
        }
        
        // 清空错误信息
        errorMessage = "";
        return "redirect:/login";
    }

    // 模拟服务层方法
    private boolean saveUserToDatabase(String username, String password) {
        // 模拟数据库约束
        if (username.length() > 20) {
            return false;
        }
        return true;
    }
}

// src/main/resources/templates/register.html
// <!DOCTYPE html>
// <html>
// <head>
//     <title>Bank Registration</title>
// </head>
// <body>
//     <h2>Register New Account</h2>
//     
//     <!-- 易受攻击的错误信息显示 -->
//     <div th:if="${error != null}" th:text="${error}"></div>
//     
//     <form action="/register" method="post">
//         <div>
//             <label>Username:
//                 <input type="text" name="username" required>
//             </label>
//         </div>
//         <div>
//             <label>Password:
//                 <input type="password" name="password" required>
//             </label>
//         </div>
//         <button type="submit">Register</button>
//     </form>
// </body>
// </html>