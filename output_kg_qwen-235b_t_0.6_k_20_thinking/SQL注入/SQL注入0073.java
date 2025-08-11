package com.example.bigdata;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 模拟大数据处理场景中的SQL注入漏洞
public class DataProcessor {
    private Connection connection;

    public DataProcessor(String dbUrl, String user, String password) throws SQLException {
        this.connection = DriverManager.getConnection(dbUrl, user, password);
        initializeSchema();
    }

    private void initializeSchema() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS sales_data (id INT PRIMARY KEY, region VARCHAR(50), amount DECIMAL(10,2))");
            // 插入测试数据
            stmt.execute("INSERT INTO sales_data (id, region, amount) VALUES (1, 'North', 1000), (2, 'South', 1500) ON CONFLICT (id) DO NOTHING");
        }
    }

    // 存在SQL注入漏洞的方法
    public List<SalesRecord> getAggregatedData(String filterRegion) {
        List<SalesRecord> results = new ArrayList<>();
        String query = "SELECT region, SUM(amount) as total FROM sales_data";
        
        // 漏洞点：直接拼接用户输入到SQL语句中
        if (filterRegion != null && !filterRegion.isEmpty()) {
            query += " WHERE region = '" + filterRegion + "'";
        }
        
        query += " GROUP BY region";

        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            while (rs.next()) {
                results.add(new SalesRecord(rs.getString("region"), rs.getDouble("total")));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return results;
    }

    public static void main(String[] args) {
        try {
            DataProcessor processor = new DataProcessor("jdbc:h2:mem:test", "sa", "");
            // 模拟用户输入
            String userInput = "North' OR '1'='1"; // 恶意输入
            List<SalesRecord> data = processor.getAggregatedData(userInput);
            
            System.out.println("查询结果:");
            for (SalesRecord record : data) {
                System.out.println(record.region + ": $" + record.total);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    static class SalesRecord {
        String region;
        double total;

        SalesRecord(String region, double total) {
            this.region = region;
            this.total = total;
        }
    }
}