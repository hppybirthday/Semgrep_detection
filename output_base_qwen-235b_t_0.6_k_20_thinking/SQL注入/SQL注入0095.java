package com.example.demo;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.web.bind.annotation.*;

import javax.annotation.PostConstruct;
import javax.sql.DataSource;
import java.util.List;
import java.util.Map;

@SpringBootApplication
public class DemoApplication {
    public static void main(String[] args) {
        SpringApplication.run(DemoApplication.class, args);
    }

    @Bean
    public DataSource dataSource() {
        return new org.apache.tomcat.jdbc.pool.DataSource();
    }

    @PostConstruct
    public void init(DataSource dataSource) {
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS users (id INT PRIMARY KEY, username VARCHAR(50), password VARCHAR(50))");
        jdbcTemplate.update("INSERT INTO users VALUES (1, 'admin', 'admin123')");
    }
}

@RestController
@Component
class UserController {
    private final JdbcTemplate jdbcTemplate;

    public UserController(DataSource dataSource) {
        this.jdbcTemplate = new JdbcTemplate(dataSource);
    }

    @PostMapping("/login")
    public String login(@RequestParam String username, @RequestParam String password) {
        String query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'";
        List<Map<String, Object>> result = jdbcTemplate.queryForList(query);
        if (!result.isEmpty()) {
            return "Login successful for " + username;
        }
        return "Invalid credentials";
    }

    @GetMapping("/users")
    public List<Map<String, Object>> getAllUsers() {
        return jdbcTemplate.queryForList("SELECT * FROM users");
    }
}