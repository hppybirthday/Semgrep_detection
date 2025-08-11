package com.example.vulnerableapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import tk.mybatis.spring.annotation.MapperScan;

import java.util.List;

@SpringBootApplication
@MapperScan("com.example.vulnerableapp.mapper")
@RestController
@RequestMapping("/api/users")
public class SqlInjectionDemo {

    public static void main(String[] args) {
        SpringApplication.run(SqlInjectionDemo.class, args);
    }

    private final UserService userService;

    public SqlInjectionDemo(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public List<User> getUsers(@RequestParam String sort) {
        return userService.findUsers(sort);
    }
}

interface UserService {
    List<User> findUsers(String sort);
}

@Service
class UserServiceImpl implements UserService {

    private final UserMapper userMapper;

    public UserServiceImpl(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    @Override
    public List<User> findUsers(String sort) {
        return userMapper.selectUsers(sort);
    }
}

@lombok.Data
class User {
    private Long id;
    private String username;
    private String email;
}

interface UserMapper {
    @Select({"<script>",
      "SELECT * FROM users WHERE username LIKE '%"
      + "${search}%'",
      "ORDER BY ${sort}",
      "</script>"})
    List<User> selectUsers(@Param("sort") String sort);
}

// application.properties配置
// spring.datasource.url=jdbc:mysql://localhost:3306/vulnerable_db
// spring.datasource.username=root
// spring.datasource.password=root
// mybatis.mapper-locations=classpath:mapper/*.xml