package com.example.mobileapp.controller;

import com.example.mobileapp.service.UserService;
import com.example.mobileapp.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;
import java.util.Map;
import java.util.HashMap;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping
    public Map<String, Object> getUsers(@RequestParam String query) {
        Map<String, Object> response = new HashMap<>();
        try {
            response.put("data", userService.searchUsers(query));
            response.put("status", "success");
        } catch (Exception e) {
            response.put("status", "error");
            response.put("message", e.getMessage());
        }
        return response;
    }
}

package com.example.mobileapp.service;

import com.example.mobileapp.mapper.UserMapper;
import com.example.mobileapp.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import java.util.List;
import java.util.Map;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public List<User> searchUsers(String query) {
        return userMapper.findUsers(query);
    }
}

package com.example.mobileapp.mapper;

import com.example.mobileapp.model.User;
import org.apache.ibatis.annotations.Select;
import java.util.List;

public interface UserMapper {
    @Select("SELECT * FROM users WHERE username LIKE '%${query}%' OR email LIKE '%${query}%'")
    List<User> findUsers(String query);
}

package com.example.mobileapp.model;

public class User {
    private Long id;
    private String username;
    private String email;
    // Getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }
}