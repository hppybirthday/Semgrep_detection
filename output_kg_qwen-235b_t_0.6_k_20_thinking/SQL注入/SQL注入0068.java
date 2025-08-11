package com.example.demo;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;

import javax.sql.DataSource;
import java.util.List;
import java.util.Map;

@Controller
public class UserController {
    private JdbcTemplate jdbcTemplate;

    @Autowired
    public void setDataSource(DataSource dataSource) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @PostMapping("/login")
    @ResponseBody
    public String login(@RequestParam String username, @RequestParam String password) {
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        List<Map<String, Object>> result = jdbcTemplate.queryForList(query);
        if (!result.isEmpty()) {
            return "Login successful!";
        }
        return "Invalid credentials";
    }

    @PostMapping("/search")
    @ResponseBody
    public List<Map<String, Object>> searchUsers(@RequestParam String keyword) {
        String query = "SELECT * FROM users WHERE username LIKE '%" + keyword + "%'";
        return jdbcTemplate.queryForList(query);
    }

    @PostMapping("/delete")
    @ResponseBody
    public String deleteUser(@RequestParam String id) {
        String query = "DELETE FROM users WHERE id = " + id;
        jdbcTemplate.update(query);
        return "User deleted";
    }

    @PostMapping("/update")
    @ResponseBody
    public String updateUser(@RequestParam String id, @RequestParam String newEmail) {
        String query = "UPDATE users SET email = '" + newEmail + "' WHERE id = " + id;
        jdbcTemplate.update(query);
        return "User updated";
    }
}

// application.properties配置：
spring.datasource.url=jdbc:mysql://localhost:3306/testdb
spring.datasource.username=root
spring.datasource.password=123456
spring.datasource.driver-class-name=com.mysql.cj.jdbc.Driver