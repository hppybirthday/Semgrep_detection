package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;
import java.util.List;
import java.util.function.Function;
import java.util.stream.Collectors;

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
    public List<User> searchUsers(@RequestParam String username,
                                   @RequestParam String mobile,
                                   @RequestParam String sort,
                                   @RequestParam String order) {
        return userService.findUsers(username, mobile, sort, order);
    }
}

@Service
class UserService {
    @Resource
    private UserMapper userMapper;

    public List<User> findUsers(String username, String mobile, String sort, String order) {
        String query = "1=1";
        if (username != null && !username.isEmpty()) {
            query += " AND username = '" + username + "'";
        }
        if (mobile != null && !mobile.isEmpty()) {
            query += " AND mobile = '" + mobile + "'";
        }
        if (sort != null && !sort.isEmpty()) {
            query += " ORDER BY " + sort + " " + order;
        }

        return userMapper.selectList(new QueryWrapper<User>().apply(query));
    }
}

@Mapper
interface UserMapper {
    @Select("SELECT * FROM users WHERE ${ew.sqlSegment}")
    List<User> selectList(@Param("ew") Wrapper<User> wrapper);
}

class User {
    private Long id;
    private String username;
    private String mobile;
    // Getters and setters
}

// MyBatis Plus config (simplified)
@Configuration
@MapperScan("com.example.demo")
class MyBatisConfig {}