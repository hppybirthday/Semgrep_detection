package com.example.vulnerableapp.controller;

import com.example.vulnerableapp.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.Map;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/search")
    public String searchUser(@RequestParam Map<String, String> params) {
        return userService.findUser(params.get("column"), params.get("value"));
    }
}

package com.example.vulnerableapp.service;

import com.example.vulnerableapp.mapper.UserMapper;
import com.example.vulnerableapp.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
public class UserService {
    @Autowired
    private UserMapper userMapper;

    public String findUser(String column, String value) {
        List<User> users = userMapper.selectByDynamicField(column, value);
        return users.isEmpty() ? "Not Found" : users.get(0).toString();
    }
}

package com.example.vulnerableapp.mapper;

import com.example.vulnerableapp.model.User;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;

import java.util.List;

public interface UserMapper {
    @Select("SELECT * FROM users WHERE ${column} = '${value}'")
    List<User> selectByDynamicField(@Param("column") String column, @Param("value") String value);
}

package com.example.vulnerableapp.model;

public class User {
    private int id;
    private String username;
    private String email;

    // Getters and setters
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    
    public String getEmail() { return email; }
    public void setEmail(String email) { this.email = email; }

    @Override
    public String toString() {
        return "User{id=" + id + ", username='" + username + "', email='" + email + "'}";
    }
}