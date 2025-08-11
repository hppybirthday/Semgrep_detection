package com.example.crawler;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class WebCrawler {
    private Connection connection;

    public WebCrawler(String dbUrl, String dbUser, String dbPassword) throws SQLException {
        this.connection = DriverManager.getConnection(dbUrl, dbUser, dbPassword);
    }

    public void processPage(String url, String content) {
        try {
            // Vulnerable SQL operation: direct string concatenation
            String sql = "INSERT INTO crawled_data (url, content) VALUES ('" + url + "', '" + content + "')";
            Statement statement = connection.createStatement();
            statement.executeUpdate(sql);
            System.out.println("Data stored successfully");
        } catch (SQLException e) {
            System.err.println("Error storing data: " + e.getMessage());
        }
    }

    public List<String> searchContent(String keyword) {
        List<String> results = new ArrayList<>();
        try {
            // Second vulnerability point: search function with SQL injection
            String sql = "SELECT url FROM crawled_data WHERE content LIKE '%" + keyword + "%'";
            Statement statement = connection.createStatement();
            ResultSet resultSet = statement.executeQuery(sql);
            
            while (resultSet.next()) {
                results.add(resultSet.getString("url"));
            }
        } catch (SQLException e) {
            System.err.println("Search error: " + e.getMessage());
        }
        return results;
    }

    public static void main(String[] args) {
        try {
            WebCrawler crawler = new WebCrawler(
                "jdbc:mysql://localhost:3306/crawler_db?useSSL=false", 
                "root", 
                "password"
            );
            
            // Simulate processing a malicious URL
            String maliciousUrl = "http://example.com/page?param='; DROP TABLE crawled_data;--";
            String maliciousContent = "Malicious content'; INSERT INTO users (username, password) VALUES ('hacker', '123456');--";
            
            crawler.processPage(maliciousUrl, maliciousContent);
            
            // Simulate search with injection
            System.out.println("Search results:");
            crawler.searchContent("nothing'; SELECT * FROM users;--");
            
        } catch (SQLException e) {
            System.err.println("Database connection error: " + e.getMessage());
        }
    }
}