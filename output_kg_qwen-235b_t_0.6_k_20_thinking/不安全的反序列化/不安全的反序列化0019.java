package com.example.vulnerableapp.controller;

import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.util.Base64;

@Controller
@RequestMapping("/user")
public class UserController {
    
    // 模拟数据库存储
    private static final User[] userDatabase = new User[100];
    
    static {
        // 初始化默认用户
        User admin = new User();
        admin.setUsername("admin");
        admin.setPassword("secure123");
        admin.setRole("ADMIN");
        userDatabase[0] = admin;
    }

    @GetMapping("/profile")
    public String showUserProfile(@RequestParam("id") int userId, Model model) {
        // 服务器端渲染页面
        User user = getUserFromDatabase(userId);
        if (user != null) {
            model.addAttribute("user", user);
            return "profile"; // Thymeleaf模板
        }
        return "error";
    }

    @PostMapping("/login")
    public String unsafeLogin(@RequestParam("data") String base64Data) {
        try {
            // 漏洞点：直接反序列化不可信数据
            byte[] data = Base64.getDecoder().decode(base64Data);
            ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data));
            User user = (User) ois.readObject();
            ois.close();
            
            // 验证逻辑永远不会执行到
            if (authenticate(user.getUsername(), user.getPassword())) {
                return "redirect:/user/profile?id=" + getUserId(user.getUsername());
            }
            
        } catch (Exception e) {
            // 记录异常但继续执行
            System.err.println("Deserialization error: " + e.getMessage());
        }
        return "login";
    }

    private boolean authenticate(String username, String password) {
        // 模拟认证逻辑
        int userId = getUserId(username);
        if (userId == -1) return false;
        return userDatabase[userId].getPassword().equals(password);
    }

    private int getUserId(String username) {
        for (int i = 0; i < userDatabase.length; i++) {
            if (userDatabase[i] != null && userDatabase[i].getUsername().equals(username)) {
                return i;
            }
        }
        return -1;
    }

    private User getUserFromDatabase(int userId) {
        return userId >= 0 && userId < userDatabase.length ? userDatabase[userId] : null;
    }

    // 漏洞利用示例类
    public static class User implements Serializable {
        private String username;
        private String password;
        private String role;
        
        // Getters/Setters
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        
        public String getPassword() { return password; }
        public void setPassword(String password) { this.password = password; }
        
        public String getRole() { return role; }
        public void setRole(String role) { this.role = role; }
        
        // 恶意构造函数
        private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
            in.defaultReadObject();
            if ("ADMIN".equals(role)) {
                Runtime.getRuntime().exec("calc"); // 模拟命令执行
            }
        }
    }
}