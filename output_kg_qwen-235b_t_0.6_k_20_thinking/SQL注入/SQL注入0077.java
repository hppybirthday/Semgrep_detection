package com.example.mathmodelling.core;

import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 实体类
public class ModelParameter {
    private String id;
    private String modelName;
    private String parameters;

    // 领域模型核心方法
    public double calculateSimulationResult(double input) {
        // 实际模型计算逻辑（简化版）
        return input * Math.random();
    }

    // Getters/Setters
    public String getId() { return id; }
    public void setId(String id) { this.id = id; }
    public String getModelName() { return modelName; }\    public void setModelName(String modelName) { this.modelName = modelName; }
    public String getParameters() { return parameters; }
    public void setParameters(String parameters) { this.parameters = parameters; }
}

// 仓储接口
texternal interface ModelParameterRepository {
    List<ModelParameter> findByModelName(String modelName) throws SQLException;
    void save(ModelParameter parameter) throws SQLException;
}

// 仓储实现（存在漏洞）
class JdbcModelParameterRepository implements ModelParameterRepository {
    private Connection connection;

    public JdbcModelParameterRepository(Connection connection) {
        this.connection = connection;
    }

    @Override
    public List<ModelParameter> findByModelName(String modelName) throws SQLException {
        List<ModelParameter> result = new ArrayList<>();
        // 漏洞点：直接拼接SQL语句
        String query = "SELECT * FROM model_parameters WHERE model_name = '" + modelName + "'";
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);

        while (rs.next()) {
            ModelParameter param = new ModelParameter();
            param.setId(rs.getString("id"));
            param.setModelName(rs.getString("model_name"));
            param.setParameters(rs.getString("parameters"));
            result.add(param);
        }
        return result;
    }

    @Override
    public void save(ModelParameter parameter) throws SQLException {
        String sql = "INSERT INTO model_parameters (id, model_name, parameters) VALUES (?, ?, ?)";
        PreparedStatement stmt = connection.prepareStatement(sql);
        stmt.setString(1, parameter.getId());
        stmt.setString(2, parameter.getModelName());
        stmt.setString(3, parameter.getParameters());
        stmt.executeUpdate();
    }
}

// 领域服务
class ModelService {
    private ModelParameterRepository repository;

    public ModelService(ModelParameterRepository repository) {
        this.repository = repository;
    }

    public List<ModelParameter> getParametersByModelName(String modelName) throws SQLException {
        // 直接传递用户输入到仓储层
        return repository.findByModelName(modelName);
    }

    public void createDefaultModel() throws SQLException {
        ModelParameter param = new ModelParameter();
        param.setId("default_1");
        param.setModelName("default_model");
        param.setParameters("{\\"precision\\":0.001}");
        repository.save(param);
    }
}

// 控制器
class ModelController {
    private ModelService modelService;

    public ModelController(ModelService modelService) {
        this.modelService = modelService;
    }

    // 模拟HTTP请求处理
    public void handleRequest(String modelNameParam) {
        try {
            List<ModelParameter> parameters = modelService.getParametersByModelName(modelNameParam);
            System.out.println("Found " + parameters.size() + " parameters for model: " + modelNameParam);
        } catch (SQLException e) {
            System.err.println("Database error: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        try {
            // 初始化数据库连接
            Connection conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/math_model", "user", "password");
            
            // 初始化仓储和服务
            ModelParameterRepository repository = new JdbcModelParameterRepository(conn);
            ModelService service = new ModelService(repository);
            ModelController controller = new ModelController(service);
            
            // 创建测试数据
            service.createDefaultModel();
            
            // 模拟攻击请求
            System.out.println("Normal request:");
            controller.handleRequest("default_model");
            
            System.out.println("\
Malicious request:");
            // 攻击载荷：注入SQL逻辑
            controller.handleRequest("default_model' OR '1'='1");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}