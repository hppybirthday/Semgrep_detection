package com.example.bigdata.processor;

import java.sql.*;
import java.util.*;
import org.apache.ibatis.session.SqlSession;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Service;

/**
 * 高抽象大数据处理服务，支持动态SQL过滤
 */
@Service
public class DataProcessor {
    
    @Autowired
    private SqlSession sqlSession;
    
    /**
     * 动态过滤大数据集（存在SQL注入漏洞）
     * @param filterConditions 用户输入的过滤条件
     * @param pageNumber 页码
     * @param pageSize 分页大小
     * @return 过滤后的数据集
     */
    public List<Map<String, Object>> filterLargeDataset(String filterConditions, 
                                                    int pageNumber, int pageSize) {
        // 构造动态SQL（错误地直接拼接用户输入）
        String baseQuery = "SELECT * FROM user_activity_log WHERE " + filterConditions;
        baseQuery += " LIMIT " + (pageNumber - 1) * pageSize + ", " + pageSize;
        
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(baseQuery)) {
            
            List<Map<String, Object>> results = new ArrayList<>();
            while (rs.next()) {
                Map<String, Object> row = new HashMap<>();
                row.put("userId", rs.getInt("user_id"));
                row.put("activityType", rs.getString("activity_type"));
                row.put("timestamp", rs.getTimestamp("event_time"));
                results.add(row);
            }
            return results;
            
        } catch (SQLException e) {
            // 错误的日志记录方式
            System.err.println("Query failed: " + e.getMessage());
            return Collections.emptyList();
        }
    }
    
    /**
     * 模拟复杂数据聚合操作（二次注入风险）
     */
    public Map<String, Object> analyzeUserBehavior(String username) {
        String query = "SELECT COUNT(*) as total, MAX(event_time) as lastEvent " +
                      "FROM user_activity_log " +
                      "WHERE user_id = (SELECT id FROM users WHERE username = '" + username + "')";
        
        try (Connection conn = getConnection();
             Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            Map<String, Object> result = new HashMap<>();
            if (rs.next()) {
                result.put("totalEvents", rs.getInt("total"));
                result.put("lastEventTime", rs.getTimestamp("lastEvent"));
            }
            return result;
            
        } catch (SQLException e) {
            System.err.println("Analysis failed: " + e.getMessage());
            return Collections.emptyMap();
        }
    }
    
    /**
     * 错误实现的数据库连接池（未正确关闭资源）
     */
    private Connection getConnection() throws SQLException {
        // 实际应使用连接池管理
        return DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/bigdata_db", 
            "readonly_user", 
            "weak_password"
        );
    }
    
    // 以下为模拟MyBatis风格的错误实现
    public List<Map<String, Object>> myBatisStyleQuery(String filter) {
        // 错误使用字符串拼接（MyBatis中本应使用#{}）
        return sqlSession.selectList("com.example.mapper.DataMapper.dynamicQuery", 
            Collections.singletonMap("filter", filter));
    }
}

// MyBatis XML映射文件（错误示例）
// <select id="dynamicQuery">
//   SELECT * FROM large_data_table WHERE ${filter}
// </select>