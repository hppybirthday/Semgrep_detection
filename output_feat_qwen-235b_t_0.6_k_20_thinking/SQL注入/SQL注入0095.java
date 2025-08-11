package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import com.baomidou.mybatisplus.core.mapper.BaseMapper;
import com.baomidou.mybatisplus.extension.service.impl.ServiceImpl;
import java.util.List;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class SqlInjectionDemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(SqlInjectionDemoApplication.class, args);
    }
}

@MapperScan("com.example.demo")
interface UserMapper extends BaseMapper<User> {
    @Select("SELECT * FROM users WHERE username LIKE '%${queryText}%' ORDER BY ${sort} ${order}")
    List<User> searchUsers(@Param("queryText") String queryText, 
                          @Param("sort") String sort, 
                          @Param("order") String order);
}

@Service
class UserService extends ServiceImpl<UserMapper, User> {
    public List<User> search(String queryText, String sort, String order) {
        return query().eq("username", queryText).list();
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
    public List<User> getUsers(@RequestParam String queryText, 
                               @RequestParam String sort, 
                               @RequestParam String order) {
        return userService.search(queryText, sort, order);
    }
}

record User(Long id, String username, String password) {}

// 漏洞点说明：
// 1. MyBatis的@Select注解中使用${}进行字符串拼接
// 2. 三个用户输入参数(queryText, sort, order)均未经过滤直接拼接SQL
// 3. 攻击者可通过参数注入UNION查询或执行恶意语句
// 示例攻击：
// queryText=abc' UNION SELECT * FROM users WHERE '1'='1
// sort=id; DROP TABLE users-- 
// order=ASC