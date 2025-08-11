package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.apache.ibatis.annotations.*;
import java.util.List;

@SpringBootApplication
@MapperScan("com.example.demo")
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }
}

@RestController
@RequestMapping("/users")
class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public List<User> getUsers(@RequestParam String username) {
        return userService.findUser(username);
    }
}

interface UserService {
    List<User> findUser(String username);
}

@Mapper
interface UserMapper {
    @Select({"<script>",
      "SELECT * FROM users WHERE username LIKE '%"${username}"%'",
      "</script>"})
    @Results({
        @Result(property = "id", column = "id"),
        @Result(property = "username", column = "username")
    })
    List<User> searchUsers(String username);
}

class UserServiceImpl implements UserService {
    private final UserMapper userMapper;

    public UserServiceImpl(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    @Override
    public List<User> findUser(String username) {
        return userMapper.searchUsers(username);
    }
}

class User {
    private Long id;
    private String username;
    // getters and setters
    public Long getId() { return id; }
    public void setId(Long id) { this.id = id; }
    public String getUsername() { return username; }
    public void setUsername(String username) { this.username = username; }
}