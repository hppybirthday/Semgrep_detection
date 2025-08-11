package com.example.ml;

import java.sql.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public class DatasetProcessor {
    private final Connection connection;

    public DatasetProcessor(String dbUrl, String user, String password) throws SQLException {
        this.connection = DriverManager.getConnection(dbUrl, user, password);
    }

    // 易受攻击的函数式数据集查询方法
    public List<String> getFeaturesByDatasetName(String datasetName) throws SQLException {
        String query = "SELECT features FROM datasets WHERE name = '" + datasetName + "'";
        
        // 函数式风格的资源管理
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            // 使用Stream API进行结果处理
            return Stream.generate(() -> {
                try {
                    if (rs.next()) {
                        return rs.getString("features");
                    }
                    return null;
                } catch (SQLException e) {
                    throw new RuntimeException(e);
                }
            })
            .takeWhile(s -> s != null)
            .collect(Collectors.toList());
        }
    }

    // 模拟机器学习特征处理流程
    public void processDataset(String datasetName) {
        try {
            List<String> features = getFeaturesByDatasetName(datasetName);
            System.out.println("Processing dataset with " + features.size() + " features");
            // 这里模拟特征处理逻辑
            
        } catch (SQLException e) {
            System.err.println("Database error: " + e.getMessage());
        }
    }

    // 模拟攻击场景
    public static void main(String[] args) {
        try {
            DatasetProcessor processor = new DatasetProcessor(
                "jdbc:mysql://localhost:3306/ml_db", 
                "ml_user", 
                "secure_password"
            );
            
            // 正常用例
            // processor.processDataset("training_data");
            
            // 恶意输入示例
            String maliciousInput = "training_data' UNION SELECT schema_name FROM information_schema.schemata -- ";
            processor.processDataset(maliciousInput);
            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}

// 数据库表结构模拟
/*
CREATE TABLE datasets (
    id INT PRIMARY KEY AUTO_INCREMENT,
    name VARCHAR(255) NOT NULL,
    features TEXT NOT NULL
);

INSERT INTO datasets (name, features) VALUES
('training_data', 'age,income,occupation'),
('test_data', 'height,weight,bmi');
*/