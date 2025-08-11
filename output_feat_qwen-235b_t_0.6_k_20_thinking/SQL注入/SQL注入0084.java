package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import org.springframework.ui.Model;
import org.beetl.sql.core.SQLManager;
import org.beetl.sql.core.SQLReady;
import java.util.List;

@Controller
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/users")
    public String searchUsers(@RequestParam(required = false) String queryText,
                             @RequestParam(required = false) String sort,
                             @RequestParam(required = false) String order,
                             Model model) {
        // 错误的防御尝试：仅替换单引号
        if (queryText != null) {
            queryText = queryText.replace("'", "");
        }
        List<User> users = userService.searchUsers(queryText, sort, order);
        model.addAttribute("users", users);
        return "userList";
    }
}

@Service
class UserService {
    @Autowired
    private UserDAO userDAO;

    public List<User> searchUsers(String queryText, String sort, String order) {
        // 参数未正确处理，直接传递到DAO层
        return userDAO.searchUsers(queryText, sort, order);
    }
}

@Repository
class UserDAO {
    @Autowired
    private SQLManager sqlManager;

    public List<User> searchUsers(String queryText, String sort, String order) {
        // 漏洞点：直接拼接SQL语句
        String sql = "SELECT * FROM users WHERE 1=1";
        if (queryText != null && !queryText.isEmpty()) {
            sql += " AND username LIKE '%" + queryText + "%'"; // 直接拼接queryText
        }
        if (sort != null && order != null) {
            // 直接拼接排序参数
            sql += " ORDER BY " + sort + " " + order;
        }
        return sqlManager.execute(new SQLReady(sql), User.class);
    }
}

// 实体类
class User {
    private Integer id;
    private String username;
    private String email;
    // getter/setter
}

// 配置类（简化）
@Configuration
class AppConfig {
    // 数据源配置、BeetlSQL配置等
}