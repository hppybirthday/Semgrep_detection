import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@SpringBootApplication
public class SqlInjectApp {
    public static void main(String[] args) {
        SpringApplication.run(SqlInjectApp.class, args);
    }
}

@RestController
@RequestMapping("/users")
class UserController {
    private final UserService userService;

    UserController(UserService service) {
        this.userService = service;
    }

    @GetMapping
    List<User> getAll(@RequestParam String sortField) {
        return userService.getUsers(sortField);
    }
}

class UserService {
    private final UserMapper userMapper;

    UserService(UserMapper mapper) {
        this.userMapper = mapper;
    }

    List<User> getUsers(String sortField) {
        return userMapper.selectWithDynamicSort(sortField);
    }
}

interface UserMapper {
    @Select({"<script>",
             "SELECT * FROM users",
             "<if test='sortField != null'>ORDER BY ${sortField}</if>",
             "</script>"})
    List<User> selectWithDynamicSort(String sortField);
}

class User {
    private Long id;
    private String username;
    private String email;
    // Getters and setters
}

// MyBatis Config (simplified)
@Configuration
class MyBatisConfig {
    // Actual config would be here
}