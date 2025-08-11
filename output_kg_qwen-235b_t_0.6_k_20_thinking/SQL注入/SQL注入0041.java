package com.example.bigdata;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;

import java.util.List;

// 模拟大数据处理服务
@RestController
@RequestMapping("/analytics")
public class DataProcessingController {
    @Autowired
    private DataProcessingService dataProcessingService;

    // 接收用户自定义查询条件
    @GetMapping("/query")
    public List<String> processQuery(@RequestParam String filters) {
        return dataProcessingService.executeCustomQuery(filters);
    }
}

@Service
class DataProcessingService {
    @Autowired
    private JdbcTemplate jdbcTemplate;

    // 存在SQL注入漏洞的核心方法
    public List<String> executeCustomQuery(String userFilters) {
        // 声明式编程风格下错误的SQL拼接
        String query = String.format("SELECT * FROM user_activity_log WHERE %s", userFilters);
        
        // 使用Spring JDBC Template的错误用法
        // 本应使用参数化查询，但开发者为图方便直接拼接字符串
        return jdbcTemplate.queryForList(query, String.class);
    }
}

// 模拟实体类
record UserActivityLog(int id, String actionType, long timestamp) {}

/*
漏洞场景示例：
正常请求：/analytics/query?filters=actionType='login'
攻击载荷：/analytics/query?filters=1=1;DROP TABLE user_activity_log--
*/