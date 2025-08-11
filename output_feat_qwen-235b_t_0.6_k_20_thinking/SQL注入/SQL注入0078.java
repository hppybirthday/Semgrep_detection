package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;
import java.util.List;

@SpringBootApplication
@RestController
@RequestMapping("/users")
public class UserController {
    @Resource
    private UserService userService;

    @GetMapping
    public List<User> getUsers(@RequestParam String id, @RequestParam String sort) {
        return userService.findUser(id, sort);
    }
}

class User {
    private String id;
    private String name;
    // getters and setters
}

interface UserService {
    List<User> findUser(String id, String sort);
}

@Repository
class UserServiceImpl implements UserService {
    @Resource
    private UserMapper userMapper;

    @Override
    public List<User> findUser(String id, String sort) {
        return userMapper.queryUser(id, sort);
    }
}

interface UserMapper {
    @Select("SELECT * FROM users WHERE id='${id}' ORDER BY ${sort}")
    List<User> queryUser(@Param("id") String id, @Param("sort") String sort);
}
// 启动类
public static void main(String[] args) {
    SpringApplication.run(UserController.class, args);
}