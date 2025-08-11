package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;
import java.util.List;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

@RestController
@RequestMapping("/users")
class UserController {
    @Resource
    UserService userService;

    @GetMapping
    List<User> getUsers(@RequestParam String orderBy) {
        return userService.getUsers(orderBy);
    }
}

interface UserService {
    List<User> getUsers(String orderBy);
}

@Service
class UserServiceImpl implements UserService {
    @Resource
    UserMapper userMapper;

    @Override
    public List<User> getUsers(String orderBy) {
        return userMapper.selectUsers(orderBy);
    }
}

interface UserMapper {
    @Select({"<script>",
              "SELECT * FROM users ORDER BY ${orderBy}",
              "</script>"})
    List<User> selectUsers(String orderBy);
}

class User {
    private Long id;
    private String name;
    // getters and setters
}

// application.yml配置（模拟云原生环境）
/*
spring:
  datasource:
    url: jdbc:mysql://localhost:3306/demo
    username: root
    password: root
*/