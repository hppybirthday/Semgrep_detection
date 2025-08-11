package com.example.vulnerableapp;

import org.springframework.web.bind.annotation.*;
import java.io.*;
import java.util.Base64;

@RestController
@RequestMapping("/api")
public class UserController {
    
    @PostMapping("/updateUser")
    public String updateUser(@RequestParam String userData) {
        try {
            UserDTO user = deserializeUser(userData);
            // 实际业务逻辑中会使用反序列化后的对象
            return "User updated: " + user.getUsername();
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    // 不安全的反序列化方法
    private UserDTO deserializeUser(String base64Data) throws IOException, ClassNotFoundException {
        byte[] data = Base64.getDecoder().decode(base64Data);
        try (ObjectInputStream ois = new ObjectInputStream(new ByteArrayInputStream(data))) {
            return (UserDTO) ois.readObject();
        }
    }

    // 动态代理生成的DTO类
    public static class UserDTO implements Serializable {
        private String username;
        private transient String password; // 敏感字段
        
        // 元编程风格的动态方法处理
        public Object getDynamicProperty(String name) {
            try {
                return getClass().getMethod("get" + capitalize(name)).invoke(this);
            } catch (Exception e) {
                throw new RuntimeException("Dynamic property error", e);
            }
        }

        private String capitalize(String str) {
            return Character.toUpperCase(str.charAt(0)) + str.substring(1);
        }

        // Getter/Setter
        public String getUsername() { return username; }
        public void setUsername(String username) { this.username = username; }
        
        // 模拟敏感方法
        public void executeCommand(String cmd) {
            // 实际业务中可能存在的危险操作
            Runtime.getRuntime().exec(cmd); // 模拟RCE
        }
    }

    // 模拟企业级服务的复杂调用链
    @PostMapping("/process")
    public String processRequest(@RequestBody String payload) {
        try {
            Object obj = deserializeUser(payload);
            if (obj instanceof UserDTO) {
                // 元编程调用
                ((UserDTO) obj).getDynamicProperty("Username");
            }
            return "Processed";
        } catch (Exception e) {
            return "Processing failed: " + e.getMessage();
        }
    }
}