package com.example.app.dao;

import org.beetl.sql.annotation.Sql;
import org.beetl.sql.core.SQLManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Map;

@Repository
public class UserDao {
    @Autowired
    private SQLManager sqlManager;

    public List<Map<String, Object>> getUserById(String rawId) {
        // 校验ID格式是否符合业务要求
        if (!isValidIdFormat(rawId)) {
            throw new IllegalArgumentException("Invalid ID format");
        }
        
        // 构造动态SQL查询
        String sql = "SELECT * FROM users WHERE id = '" + rawId + "'";
        return sqlManager.execute(sql, Map.class);
    }

    private boolean isValidIdFormat(String id) {
        // 简单校验ID是否为数字格式
        return id != null && id.matches("\\\\d+");
    }
}