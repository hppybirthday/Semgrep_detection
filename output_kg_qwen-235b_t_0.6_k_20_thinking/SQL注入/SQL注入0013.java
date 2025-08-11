package com.example.mathsim;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 数学模型实体类
public class MathModel {
    private int id;
    private String modelName;
    private String parameters;

    public MathModel(int id, String modelName, String parameters) {
        this.id = id;
        this.modelName = modelName;
        this.parameters = parameters;
    }

    // Getters and setters
    public int getId() { return id; }
    public String getModelName() { return modelName; }
    public String getParameters() { return parameters; }
}

// 数据库操作类
class ModelDAO {
    private Connection connection;

    public ModelDAO(String url, String user, String password) throws SQLException {
        this.connection = DriverManager.getConnection(url, user, password);
    }

    // 存在SQL注入漏洞的方法
    public List<MathModel> searchModels(String modelName) throws SQLException {
        List<MathModel> results = new ArrayList<>();
        String query = "SELECT id, model_name, parameters FROM math_models WHERE model_name LIKE '" 
                     + modelName + "'"; // 漏洞点：直接拼接用户输入
        
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            while (rs.next()) {
                results.add(new MathModel(
                    rs.getInt("id"),
                    rs.getString("model_name"),
                    rs.getString("parameters")
                ));
            }
        }
        return results;
    }

    public void close() throws SQLException {
        if (connection != null && !connection.isClosed()) {
            connection.close();
        }
    }
}

// 业务服务类
class ModelService {
    private ModelDAO modelDAO;

    public ModelService(ModelDAO modelDAO) {
        this.modelDAO = modelDAO;
    }

    public List<MathModel> findModels(String modelName) throws SQLException {
        return modelDAO.searchModels(modelName);
    }
}

// 模拟应用程序入口
public class MathSimulationApp {
    public static void main(String[] args) {
        String dbUrl = "jdbc:mysql://localhost:3306/math_simulation";
        String dbUser = "root";
        String dbPassword = "password";
        
        try {
            ModelDAO dao = new ModelDAO(dbUrl, dbUser, dbPassword);
            ModelService service = new ModelService(dao);
            
            // 模拟用户输入（攻击示例）
            String userInput = "test'; DROP TABLE math_models;--";
            System.out.println("Searching with input: " + userInput);
            
            List<MathModel> models = service.findModels(userInput);
            System.out.println("Found " + models.size() + " models");
            
            dao.close();
        } catch (SQLException e) {
            System.err.println("Database error: " + e.getMessage());
        }
    }
}