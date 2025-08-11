package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@Controller
@SpringBootApplication
public class XssVulnerableApp {

    // 模拟用户数据库
    private static final Map<String, String> USERS = new HashMap<>();
    static {
        USERS.put("admin", "Admin User");
    }

    public static void main(String[] args) {
        SpringApplication.run(XssVulnerableApp.class, args);
    }

    @GetMapping("/search")
    @ResponseBody
    public String searchUser(@RequestParam String username) {
        // 漏洞点：直接将用户输入拼接到HTML响应中
        if (!USERS.containsKey(username)) {
            return "<div class='error'>User <b>" + username + "</b> not found</div>";
        }
        return "<div>User <b>" + USERS.get(username) + "</b> found</div>";
    }

    @GetMapping("/profile")
    @ResponseBody
    public String userProfile(@RequestParam String name, @RequestParam String bio) {
        // 更危险的漏洞点：允许用户提交包含HTML的内容
        return "<div class='profile'>"
               + "<h1>" + name + "</h1>" 
               + "<p>" + bio + "</p>"
               + "</div>";
    }

    // 模拟错误日志记录（将用户输入写入日志）
    @GetMapping("/login")
    @ResponseBody
    public String login(@RequestParam String user, @RequestParam String pass) {
        // 仅用于演示：即使不直接返回HTML，错误日志也可能成为攻击面
        if (!USERS.containsKey(user)) {
            System.out.println("[ERROR] Failed login for user: " + user);
            return "Invalid username";
        }
        return "Login successful";
    }
}