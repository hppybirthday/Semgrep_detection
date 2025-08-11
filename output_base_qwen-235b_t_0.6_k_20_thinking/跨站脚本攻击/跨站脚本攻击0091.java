package com.example.bank;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class BankApplication {
    public static void main(String[] args) {
        SpringApplication.run(BankApplication.class, args);
    }
}

@Controller
class UserController {
    private List<User> users = new ArrayList<>();

    @GetMapping("/register")
    public String showRegistrationForm(Model model) {
        model.addAttribute("user", new User());
        return "register";
    }

    @PostMapping("/register")
    public String registerUser(@ModelAttribute("user") User user) {
        users.add(user);
        return "redirect:/users";
    }

    @GetMapping("/users")
    public String listUsers(Model model) {
        model.addAttribute("users", users);
        return "users";
    }
}

class User {
    private String username;
    private String remark; // 存在XSS风险的字段

    // Getters and setters
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getRemark() { return remark; }
    public void setRemark(String remark) { this.remark = remark; }
}

// Thymeleaf模板 register.html
// <form th:action="@{/register}" th:object="${user}" method="post">
//   用户名: <input type="text" th:field="*{username}"><br>
//   备注: <input type="text" th:field="*{remark}"><br>
//   <input type="submit" value="注册">
// </form>

// Thymeleaf模板 users.html
// <div th:each="user : ${users}">
//   <p>用户名: <span th:text="${user.username}"></span></p>
//   <p>备注: <span th:utext="${user.remark}"></span></p> <!-- 存在XSS漏洞的代码 -->
//   <hr>
// </div>