package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.Map;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

@Controller
@RequestMapping("/users")
class UserController {
    private final Map<String, User> userStore = new HashMap<>();

    @GetMapping("/{id}")
    public @ResponseBody String getUser(@PathVariable String id) {
        User user = userStore.get(id);
        if (user == null) return "User not found";
        
        // 漏洞点：直接拼接用户输入内容到HTML响应中
        return String.format("<div class='profile'>\
" + 
            "<h1>%s</h1>\
" + 
            "<div class='bio'>%s</div>\
" + 
            "<script src='%s'></script>\
" + 
            "</div>", 
            user.name, user.bio, user.theme);
    }

    @PostMapping
    public @ResponseBody String createUser(@RequestParam String id, 
                                            @RequestParam String name, 
                                            @RequestParam String bio, 
                                            @RequestParam String theme) {
        userStore.put(id, new User(name, bio, theme));
        return "User created";
    }
}

class User {
    String name;
    String bio;
    String theme;

    public User(String name, String bio, String theme) {
        this.name = name;
        this.bio = bio;
        this.theme = theme;
    }
}