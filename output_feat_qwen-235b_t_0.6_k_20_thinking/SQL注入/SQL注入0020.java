package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;
import org.apache.ibatis.annotations.*;
import java.util.List;

@SpringBootApplication
@MapperScan("com.example.demo.mapper")
public class SqlInjectionDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SqlInjectionDemoApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/users")
class UserController {
    @Autowired
    private UserService userService;

    @GetMapping
    public List<User> getUsers(@RequestParam("ids[]") String[] ids) {
        return userService.getUsersByIds(ids);
    }
}

@Service
class UserService {
    @Autowired
    private UserMapper userMapper;

    public List<User> getUsersByIds(String[] ids) {
        // 危险操作：直接拼接数组参数到SQL
        String idList = String.join(",", ids);
        return userMapper.findUsersByIds(idList);
    }
}

@Mapper
interface UserMapper {
    // 使用${}导致SQL注入漏洞
    @Select("SELECT * FROM users WHERE id IN (${ids})")
    List<User> findUsersByIds(@Param("ids") String ids);
}

// User实体类
class User {
    private Long id;
    private String username;
    private String email;
    // 省略getter/setter
}