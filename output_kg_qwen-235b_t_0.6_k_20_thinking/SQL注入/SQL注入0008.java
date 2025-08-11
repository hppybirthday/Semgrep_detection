package com.example.ml;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class SqlInjectionDemo {
    private final JdbcTemplate jdbcTemplate;

    public SqlInjectionDemo(JdbcTemplate jdbcTemplate) {
        this.jdbcTemplate = jdbcTemplate;
    }

    @GetMapping("/predict")
    public String predict(@RequestParam String feature) {
        String query = "SELECT model_output FROM ml_models WHERE feature_name = '" + feature + "'";
        List<Map<String, Object>> result = jdbcTemplate.queryForList(query);
        return result.isEmpty() ? "No prediction found" : result.get(0).get("model_output").toString();
    }

    public static void main(String[] args) {
        SpringApplication.run(SqlInjectionDemo.class, args);
    }
}

// Vulnerable code structure:
// 1. Direct string concatenation in SQL query
// 2. No input validation/filtering
// 3. Exposes database structure through error messages
// 4. Uses raw JDBC without prepared statements
// 5. Returns sensitive data without sanitization