package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import javax.servlet.http.HttpServletRequest;
import java.util.List;

@SpringBootApplication
public class SqlInjectionDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SqlInjectionDemoApplication.class, args);
    }
}

@RestController
@RequestMapping("/api/users")
class UserController {
    private final UserService userService;

    public UserController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping
    public List<User> getUsers(HttpServletRequest request) {
        String sortField = request.getParameter("sort");
        // 模拟大数据分页处理
        return userService.getUsersWithDynamicSort(sortField);
    }
}

interface UserMapper extends BaseMapper<User> {
    @Select("SELECT * FROM users ORDER BY ${sortField}")
    List<User> selectWithDynamicOrder(@Param("sortField") String sortField);
}

@Service
class UserService {
    private final UserMapper userMapper;

    public UserService(UserMapper userMapper) {
        this.userMapper = userMapper;
    }

    public List<User> getUsersWithDynamicSort(String sortField) {
        // 元编程风格动态构建ORDER BY子句
        // 错误地将用户输入直接拼接到SQL中
        return userMapper.selectWithDynamicOrder(sortField);
    }
}

@TableName("users")
class User {
    private Long id;
    private String name;
    private Integer age;
    // 省略getter/setter
}

// MyBatis Plus配置类（简化版）
@Configuration
class MyBatisPlusConfig {
    // 实际应包含正确配置...
}