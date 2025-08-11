package com.example.crawler;

import java.lang.reflect.Field;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;

// 模拟网络爬虫存储数据的类
public class WebCrawler {
    
    // 反射动态处理数据的元编程示例
    public static class PageData {
        public String url;
        public String title;
        public String content;
        
        public PageData(String url, String title, String content) {
            this.url = url;
            this.title = title;
            this.content = content;
        }
    }
    
    // 模拟爬虫处理
    public static void main(String[] args) {
        // 模拟接收用户输入的URL参数（可能包含恶意输入）
        String userInputUrl = "http://example.com/page?title=malicious' OR 1=1; DROP TABLE pages;--";
        
        // 解析URL获取数据（简化处理）
        String[] parts = userInputUrl.split("?");
        Map<String, String> params = new HashMap<>();
        if (parts.length > 1) {
            for (String param : parts[1].split("&")) {
                String[] kv = param.split("=");
                params.put(kv[0], kv[1]);
            }
        }
        
        // 创建数据对象
        PageData data = new PageData(
            parts[0],
            params.getOrDefault("title", "default_title"),
            "Scraped content here"
        );
        
        // 存储数据（存在漏洞）
        saveToDatabase(data);
    }
    
    // 使用反射动态生成SQL的危险方法
    private static void saveToDatabase(PageData data) {
        try (Connection conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/crawler_db", "user", "password")) {
            // 反射获取所有字段
            StringBuilder columns = new StringBuilder();
            StringBuilder values = new StringBuilder();
            
            for (Field field : data.getClass().getDeclaredFields()) {
                field.setAccessible(true);
                Object value = field.get(data);
                
                if (value != null) {
                    if (columns.length() > 0) {
                        columns.append(", ");
                        values.append(", ");
                    }
                    columns.append(field.getName());
                    // 危险的字符串拼接（无参数化查询）
                    values.append("'" + value.toString() + "'");
                }
            }
            
            // 构造SQL语句（存在SQL注入漏洞）
            String sql = String.format("INSERT INTO pages (%s) VALUES (%s)", 
                columns.toString(), values.toString());
            
            // 执行SQL
            conn.createStatement().executeUpdate(sql);
            
        } catch (SQLException | IllegalAccessException e) {
            e.printStackTrace();
        }
    }
}

// 数据库表结构模拟
/*
CREATE TABLE pages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    url VARCHAR(255),
    title VARCHAR(255),
    content TEXT
);
*/