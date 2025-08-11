package com.example.demo.controller;

import com.example.demo.service.UserService;
import com.example.demo.model.User;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/users")
public class UserController {
    @Autowired
    private UserService userService;

    @PostMapping("/batch")
    public String batchInsert(@RequestBody List<User> users) {
        try {
            userService.batchInsertUsers(users);
            return "Success";
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
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

    public void batchInsertUsers(List<User> users) {
        // 防御式编程：参数校验（仅检查空值）
        if (users == null || users.isEmpty()) {
            throw new IllegalArgumentException("User list cannot be empty");
        }
        userMapper.batchInsert(users);
    }
}

package com.example.demo.mapper;

import com.example.demo.model.User;
import org.apache.ibatis.annotations.Param;
import org.apache.ibatis.annotations.Select;
import org.apache.ibatis.annotations.Insert;

import java.util.List;

public interface UserMapper {
    @Insert({"<script>",
      "INSERT INTO users (username, password) VALUES",
      "<foreach item='user' collection='list' separator=','>",
        "('${user.username}', #{user.password})",  // SQL注入点：username使用${}拼接
      "</foreach>",
      "</script>"})
    void batchInsert(List<User> users);

    @Select("SELECT * FROM users WHERE username = #{username}")
    List<User> findByUsername(String username);
}

package com.example.demo.model;

public class User {
    private String username;
    private String password;

    // Getters and setters
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
    public String getPassword() { return password; }
    public void setPassword(String password) { this.password = password; }
}