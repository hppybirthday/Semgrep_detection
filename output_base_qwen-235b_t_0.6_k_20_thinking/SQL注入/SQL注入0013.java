import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 数学模型配置类
class ModelConfig {
    private String name;
    private double parameterA;
    private int iterationCount;

    public ModelConfig(String name, double parameterA, int iterationCount) {
        this.name = name;
        this.parameterA = parameterA;
        this.iterationCount = iterationCount;
    }

    // Getters
    public String getName() { return name; }
    public double getParameterA() { return parameterA; }
    public int getIterationCount() { return iterationCount; }
}

// 数据库操作类
class SimulationDatabase {
    private Connection connection;

    public SimulationDatabase(String url, String user, String password) throws SQLException {
        this.connection = DriverManager.getConnection(url, user, password);
    }

    // 存在SQL注入漏洞的方法
    public List<ModelConfig> findModelsByName(String modelName) throws SQLException {
        List<ModelConfig> results = new ArrayList<>();
        Statement stmt = connection.createStatement();
        // 危险的拼接方式
        ResultSet rs = stmt.executeQuery(
            "SELECT name, param_a, iterations FROM simulation_models WHERE name = '" + modelName + "'"
        );
        
        while (rs.next()) {
            results.add(new ModelConfig(
                rs.getString("name"),
                rs.getDouble("param_a"),
                rs.getInt("iterations")
            ));
        }
        return results;
    }

    // 安全的插入方法（未使用）
    public void addModel(ModelConfig config) throws SQLException {
        PreparedStatement pstmt = connection.prepareStatement(
            "INSERT INTO simulation_models (name, param_a, iterations) VALUES (?, ?, ?)"
        );
        pstmt.setString(1, config.getName());
        pstmt.setDouble(2, config.getParameterA());
        pstmt.setInt(3, config.getIterationCount());
        pstmt.executeUpdate();
    }
}

public class SimulationApp {
    public static void main(String[] args) {
        try {
            SimulationDatabase db = new SimulationDatabase(
                "jdbc:mysql://localhost:3306/math_models", "user", "password");
            
            // 模拟用户输入
            String userInput = "'; DROP TABLE simulation_models; --"; // 恶意输入
            System.out.println("搜索模型: " + userInput);
            
            List<ModelConfig> models = db.findModelsByName(userInput);
            for (ModelConfig model : models) {
                System.out.println("找到模型: " + model.getName());
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}