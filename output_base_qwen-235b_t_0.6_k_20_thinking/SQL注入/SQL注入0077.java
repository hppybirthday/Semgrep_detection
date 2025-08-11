package com.mathsim.core.experiment;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Scanner;

// 领域实体类
public class Experiment {
    private String id;
    private String name;
    private String result;
    
    public Experiment(String id, String name, String result) {
        this.id = id;
        this.name = name;
        this.result = result;
    }
    
    // 数据访问层（存在漏洞的实现）
    public static class ExperimentRepository {
        private Connection connection;
        
        public ExperimentRepository() throws SQLException {
            connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/mathsim_db", "user", "password");
        }
        
        // 漏洞点：直接拼接SQL语句
        public List<Experiment> findExperimentsByModel(String modelId) throws SQLException {
            Statement stmt = connection.createStatement();
            String query = "SELECT * FROM experiments WHERE model_id = '" + modelId + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            List<Experiment> results = new ArrayList<>();
            while (rs.next()) {
                results.add(new Experiment(
                    rs.getString("id"),
                    rs.getString("name"),
                    rs.getString("result")
                ));
            }
            return results;
        }
    }
    
    // 领域服务
    public static class ExperimentService {
        private ExperimentRepository repository;
        
        public ExperimentService() {
            try {
                repository = new ExperimentRepository();
            } catch (SQLException e) {
                throw new RuntimeException("Database connection failed");
            }
        }
        
        public List<Experiment> getExperimentsByModel(String modelId) {
            try {
                return repository.findExperimentsByModel(modelId);
            } catch (SQLException e) {
                throw new RuntimeException("Query execution failed");
            }
        }
    }
    
    // 模拟客户端代码
    public static void main(String[] args) {
        ExperimentService service = new ExperimentService();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("Enter model ID to search:");
        String modelId = scanner.nextLine();
        
        List<Experiment> experiments = service.getExperimentsByModel(modelId);
        
        System.out.println("Found experiments:");
        for (Experiment exp : experiments) {
            System.out.println("ID: " + exp.id + ", Name: " + exp.name);
        }
    }
}

// 数据库初始化脚本（示例）
/*
CREATE TABLE experiments (
    id VARCHAR(36) PRIMARY KEY,
    name VARCHAR(255),
    model_id VARCHAR(255),
    result TEXT
);

INSERT INTO experiments VALUES
('1', 'Model A Test', 'MODEL_A', 'Success'),
('2', 'Model B Validation', 'MODEL_B', 'Pending');
*/