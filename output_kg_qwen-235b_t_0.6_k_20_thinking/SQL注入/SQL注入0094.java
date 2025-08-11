package com.example.vulnerableapp;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.util.List;

@RestController
@RequestMapping("/api/users")
public class UserController {
    @Autowired
    private UserService userService;

    @GetMapping("/search")
    public List<User> searchUsers(@RequestParam String username, HttpServletResponse response) throws IOException {
        try {
            return userService.findUserByUsername(username);
        } catch (Exception e) {
            response.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Database error");
            return null;
        }
    }
}

@Service
class UserService {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    public List<User> findUserByUsername(String username) {
        // 漏洞点：直接拼接SQL语句
        String query = "SELECT id,username,email FROM users WHERE username = '" + username + "'";
        return jdbcTemplate.query(query, (rs, rowNum) ->
            new User(rs.getInt("id"), rs.getString("username"), rs.getString("email"))
        );
    }
}

// User.java
record User(int id, String username, String email) {}

// application.properties配置（模拟）
// spring.datasource.url=jdbc:mysql://localhost:3306/vulnerable_db
// spring.datasource.username=root
// spring.datasource.password=secret
// spring.jpa.hibernate.ddl-auto=update