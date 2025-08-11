package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

@RestController
class UserController {
    private Map<String, String> users = new HashMap<>();

    public UserController() {
        users.put("admin", "Admin User");
        users.put("guest", "Guest User");
    }

    @GetMapping("/user")
    public void getUser(@RequestParam String name, HttpServletResponse response) throws IOException {
        response.setContentType("text/html");
        PrintWriter out = response.getWriter();
        
        // 模拟动态模板渲染漏洞
        String template = "<html><body><h1>Welcome, %s</h1>\
" +
                         "<div>Last login: <span id='login'>%s</span></div>\
" +
                         "<script>\
" +
                         "document.getElementById('login').innerHTML = '%s';\
" +
                         "</script></body></html>";

        String lastLogin = String.format("%s<script>alert(1)</script>", users.getOrDefault(name, "Unknown"));
        
        // 存在漏洞的代码：直接拼接用户输入到HTML响应中
        out.printf(template, name, lastLogin, lastLogin);
    }

    @PostMapping("/update")
    public void updateUser(@RequestParam String name, @RequestParam String fullname) {
        users.put(name, fullname);
    }
}
// 编译运行后访问：http://localhost:8080/user?name=admin<script>alert(1)</script>