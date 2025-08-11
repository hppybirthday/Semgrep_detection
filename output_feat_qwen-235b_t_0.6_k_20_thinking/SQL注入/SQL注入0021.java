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
    private UserService userService;

    @GetMapping
    public List<User> getUsersByIds(@RequestParam String ids) {
        return userService.findUsersByIds(ids);
    }
}

@Service
class UserService {
    @Resource
    private UserMapper userMapper;

    public List<User> findUsersByIds(String ids) {
        return userMapper.selectUsers(ids);
    }
}

@Mapper
class UserMapper {
    // 存在漏洞的SQL注入点：直接拼接字符串参数
    @Select({"<script>",
             "SELECT * FROM users WHERE id IN (${ids})",
             "</script>"})
    List<User> selectUsers(String ids);
}

record User(Long id, String name) {}
