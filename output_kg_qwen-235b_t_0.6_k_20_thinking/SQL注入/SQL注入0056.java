package com.example.mlapp.controller;

import com.example.mlapp.service.DataService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;
import java.util.Map;

@RestController
@RequestMapping("/api/ml")
public class MLDataController {
    @Autowired
    private DataService dataService;

    @GetMapping("/predict")
    public List<Map<String, Object>> predict(@RequestParam String featureName, @RequestParam String featureValue) {
        return dataService.findTrainingData(featureName, featureValue);
    }
}

package com.example.mlapp.service;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;

import java.util.List;
import java.util.Map;

@Service
public class DataService {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    public List<Map<String, Object>> findTrainingData(String featureName, String featureValue) {
        // 漏洞点：直接拼接SQL语句
        String query = "SELECT * FROM training_data WHERE " + featureName + " = " + featureValue;
        System.out.println("执行查询: " + query);
        return jdbcTemplate.queryForList(query);
    }

    public void saveTrainingData(String dataJson) {
        String sql = "INSERT INTO training_data (features) VALUES ('" + dataJson + "')";
        jdbcTemplate.update(sql);
    }
}

package com.example.mlapp.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

import javax.sql.DataSource;

@Configuration
public class DBConfig {
    @Bean
    public DataSource dataSource() {
        DriverManagerDataSource dataSource = new DriverManagerDataSource();
        dataSource.setDriverClassName("org.h2.Driver");
        dataSource.setUrl("jdbc:h2:mem:testdb");
        dataSource.setUsername("sa");
        dataSource.setPassword("");
        return dataSource;
    }
}

// application.properties配置
// spring.datasource.url=jdbc:h2:mem:testdb
// spring.datasource.driver-class-name=org.h2.Driver
// spring.datasource.username=sa
// spring.datasource.password=
// spring.h2.console.enabled=true