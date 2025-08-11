package com.example.mathsim;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.*;

import javax.sql.DataSource;
import java.util.List;
import java.util.Map;

@SpringBootApplication
public class MathSimApplication {

    public static void main(String[] args) {
        SpringApplication.run(MathSimApplication.class, args);
    }

    @RestController
    @RequestMapping("/api/simulation")
    public static class SimulationController {
        private final JdbcTemplate jdbcTemplate;

        public SimulationController(DataSource dataSource) {
            this.jdbcTemplate = new JdbcTemplate(dataSource);
        }

        // 易受攻击的接口：根据模型参数名称查询值
        @GetMapping("/param")
        public String getParameterValue(@RequestParam String paramName) {
            String query = "SELECT value FROM simulation_params WHERE name = '" + paramName + "'";
            try {
                Map<String, Object> result = jdbcTemplate.queryForMap(query);
                return "Parameter value: " + result.get("value");
            } catch (Exception e) {
                return "Error: " + e.getMessage();
            }
        }

        // 初始化数据库表（简化示例）
        @Bean
        public void initDatabase(DataSource dataSource) {
            JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
            jdbcTemplate.execute("CREATE TABLE IF NOT EXISTS simulation_params (" +
                    "id INT PRIMARY KEY AUTO_INCREMENT, " +
                    "name VARCHAR(255) NOT NULL, " +
                    "value TEXT NOT NULL)");
            // 插入示例数据
            if (jdbcTemplate.queryForList("SELECT COUNT(*) FROM simulation_params").get(0).get("COUNT(*)").equals(0)) {
                jdbcTemplate.update("INSERT INTO simulation_params (name, value) VALUES 
                    ("ModelA_alpha", "0.75"),
                    ("ModelA_beta", "1.25"),
                    ("ModelB_threshold", "50.0")");
            }
        }
    }
}