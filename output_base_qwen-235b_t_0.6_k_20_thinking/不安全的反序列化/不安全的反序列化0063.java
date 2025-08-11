package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.io.*;
import java.util.Base64;

@SpringBootApplication
public class UserServiceApplication {
    public static void main(String[] args) {
        SpringApplication.run(UserServiceApplication.class, args);
    }
}

@RestController
@RequestMapping("/users")
class UserController {
    @PostMapping("/deserialize")
    public String deserializeUser(@RequestParam String data) throws IOException, ClassNotFoundException {
        // 模拟微服务间通信中的序列化数据处理
        byte[] decodedBytes = Base64.getDecoder().decode(data);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(decodedBytes))) {
            // 不安全的反序列化操作
            User user = (User) ois.readObject();
            return "Deserialized user: " + user.toString();
        }
    }
}

class User implements Serializable {
    private String username;
    private String role;

    public User(String username, String role) {
        this.username = username;
        this.role = role;
    }

    // 模拟业务方法
    public String getAccessLevel() {
        return "User: " + username + ", Role: " + role;
    }

    @Override
    public String toString() {
        return "User{username='" + username + '\\'', role='" + role + '\\'' + '}';
    }

    // 恶意构造方法：当反序列化时自动执行命令
    private void readObject(ObjectInputStream ois) throws IOException, ClassNotFoundException {
        ois.defaultReadObject();
        if (role != null && role.equals("admin")) {
            // 模拟攻击载荷：实际攻击中可能执行任意命令
            Runtime.getRuntime().exec("calc"); // 漏洞触发点
        }
    }
}