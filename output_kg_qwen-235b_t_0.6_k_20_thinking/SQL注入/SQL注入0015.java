package com.example.demo.controller;

import com.example.demo.service.UserService;
import com.example.demo.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/search")
    public List<User> searchUsers(@RequestParam String username) {
        return userService.searchUsers(username);
    }
}

package com.example.demo.service;

import com.example.demo.mapper.UserMapper;
import com.example.demo.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public List<User> searchUsers(String username) {
        return userMapper.searchByUsername(username);
    }
}

package com.example.demo.mapper;

import com.example.demo.model.User;
import org.apache.ibatis.annotations.Select;
import java.util.List;

public interface UserMapper {
    @Select("SELECT * FROM users WHERE username = '${username}'")
    List<User> searchByUsername(String username);
}

package com.example.demo.model;

public class User {
    private Long id;
    private String username;
    private String email;

    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}

package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}