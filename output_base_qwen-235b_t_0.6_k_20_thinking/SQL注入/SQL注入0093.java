import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 数据库连接管理类
class DatabaseConnection {
    private static Connection connection;
    
    private DatabaseConnection() {}
    
    public static Connection getInstance() {
        try {
            if (connection == null || connection.isClosed()) {
                connection = DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/mathmodels",
                    "root",
                    "password"
                );
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return connection;
    }
}

// 数学模型类
class MathematicalModel {
    private int id;
    private String name;
    private String equations;
    
    public MathematicalModel(int id, String name, String equations) {
        this.id = id;
        this.name = name;
        this.equations = equations;
    }
    
    // Getters...
    public String getName() { return name; }
}

// 模型管理类（存在漏洞）
class ModelManager {
    public List<MathematicalModel> findModelsByName(String modelName) {
        List<MathematicalModel> results = new ArrayList<>();
        Connection conn = DatabaseConnection.getInstance();
        
        try {
            Statement stmt = conn.createStatement();
            // 漏洞点：直接拼接SQL语句
            String query = "SELECT * FROM models WHERE name = '" 
                          + modelName + "'";
            ResultSet rs = stmt.executeQuery(query);
            
            while (rs.next()) {
                results.add(new MathematicalModel(
                    rs.getInt("id"),
                    rs.getString("name"),
                    rs.getString("equations")
                ));
            }
        } catch (SQLException e) {
            System.out.println("查询异常: " + e.getMessage());
        }
        
        return results;
    }
    
    // 模型初始化方法
    public void initializeDefaultModels() {
        Connection conn = DatabaseConnection.getInstance();
        try {
            Statement stmt = conn.createStatement();
            stmt.execute("CREATE TABLE IF NOT EXISTS models (" +
                "id INT PRIMARY KEY AUTO_INCREMENT, " +
                "name VARCHAR(255) NOT NULL, " +
                "equations TEXT)");
            
            // 插入测试数据
            stmt.execute("INSERT INTO models (name, equations) " +
                "SELECT 'LorenzAttractor', 'dx/dt = σ(y-x)\
dy/dt = x(ρ-z)-y\
dz/dt = xy-βz' " +
                "WHERE NOT EXISTS (SELECT 1 FROM models WHERE name='LorenzAttractor')");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}

// 主程序
class Main {
    public static void main(String[] args) {
        ModelManager manager = new ModelManager();
        manager.initializeDefaultModels();
        
        // 模拟用户输入
        String userInput = "LorenzAttractor' OR '1'='1"; // 恶意输入
        System.out.println("搜索模型: " + userInput);
        
        List<MathematicalModel> models = manager.findModelsByName(userInput);
        System.out.println("匹配结果: " + models.size() + " 个模型");
        
        for (MathematicalModel model : models) {
            System.out.println("- " + model.getName());
        }
    }
}