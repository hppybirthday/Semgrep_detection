package com.example.mathsim.db;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

public class ModelService {
    private Connection connection;

    public ModelService(String dbUrl, String user, String password) throws SQLException {
        this.connection = DriverManager.getConnection(dbUrl, user, password);
    }

    public List<Model> findModels(String modelName) throws SQLException {
        List<Model> results = new ArrayList<>();
        Statement stmt = connection.createStatement();
        String query = "SELECT id, name, parameters FROM simulation_models WHERE name = '" + modelName + "'";
        ResultSet rs = stmt.executeQuery(query);

        while (rs.next()) {
            Model model = new Model();
            model.setId(rs.getInt("id"));
            model.setName(rs.getString("name"));
            model.setParameters(rs.getString("parameters"));
            results.add(model);
        }

        rs.close();
        stmt.close();
        return results;
    }

    public void createModelTable() throws SQLException {
        Statement stmt = connection.createStatement();
        String sql = "CREATE TABLE IF NOT EXISTS simulation_models " +
                     "(id INTEGER PRIMARY KEY AUTOINCREMENT, " +
                     "name TEXT NOT NULL, " +
                     "parameters TEXT, " +
                     "created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)";
        stmt.executeUpdate(sql);
        stmt.close();
    }

    public static void main(String[] args) {
        try {
            ModelService service = new ModelService("jdbc:sqlite::memory:", "", "");
            service.createModelTable();
            
            // 模拟用户输入
            String userInput = "test'; DROP TABLE simulation_models; --";
            List<Model> models = service.findModels(userInput);
            
            System.out.println("Found " + models.size() + " models");
            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}

class Model {
    private int id;
    private String name;
    private String parameters;

    // Getters and setters
    public int getId() { return id; }
    public void setId(int id) { this.id = id; }
    
    public String getName() { return name; }
    public void setName(String name) { this.name = name; }
    
    public String getParameters() { return parameters; }
    public void setParameters(String parameters) { this.parameters = parameters; }
}