package com.example.mlapp;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
@RestController
@RequestMapping("/api")
public class SQLiDemo {
    private static final String DB_URL = "jdbc:h2:mem:testdb";
    private static final String DB_USER = "sa";
    private static final String DB_PASSWORD = "";

    public static void main(String[] args) throws Exception {
        SpringApplication.run(SQLiDemo.class, args);
        initializeDatabase();
    }

    private static void initializeDatabase() throws SQLException {
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement()) {
            stmt.execute("CREATE TABLE training_data (id INT PRIMARY KEY, feature VARCHAR(100), label FLOAT)"));
            stmt.execute("INSERT INTO training_data VALUES (1, 'age', 0.5), (2, 'income', 0.7)");
        }
    }

    @GetMapping("/data")
    public List<DataPoint> getTrainingData(@RequestParam String feature) {
        List<DataPoint> results = new ArrayList<>();
        try (Connection conn = DriverManager.getConnection(DB_URL, DB_USER, DB_PASSWORD);
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(
                 "SELECT * FROM training_data WHERE feature = '" + feature + "'") // Vulnerable line
        ) {
            while (rs.next()) {
                results.add(new DataPoint(rs.getInt("id"), rs.getString("feature"), rs.getFloat("label")));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return results;
    }

    static class DataPoint {
        int id;
        String feature;
        float label;

        DataPoint(int id, String feature, float label) {
            this.id = id;
            this.feature = feature;
            this.label = label;
        }
    }
}
// 编译运行后访问：
// curl "http://localhost:8080/api/data?feature=age" 正常查询
// curl "http://localhost:8080/api/data?feature=age' OR '1'='1" SQL注入攻击示例