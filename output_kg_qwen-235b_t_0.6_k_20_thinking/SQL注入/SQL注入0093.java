import java.sql.*;
import java.util.ArrayList;
import java.util.List;

// 数学模型实体类
class MathModel {
    private int id;
    private String name;
    private String parameters;
    private Timestamp timestamp;

    // 构造方法/Getter/Setter省略
    public MathModel(String name, String parameters) {
        this.name = name;
        this.parameters = parameters;
        this.timestamp = new Timestamp(System.currentTimeMillis());
    }
}

// 数据库操作类
class MathModelDAO {
    private Connection connection;

    public MathModelDAO() throws SQLException {
        connection = DriverManager.getConnection(
            "jdbc:h2:mem:testdb", "sa", "");
        createTable();
    }

    private void createTable() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS models (" +
                "id INT PRIMARY KEY AUTO_INCREMENT, " +
                "name VARCHAR(255), " +
                "parameters TEXT, " +
                "timestamp TIMESTAMP)");
        }
    }

    // 存在SQL注入漏洞的删除方法
    public void deleteModel(String modelName) throws SQLException {
        String query = "DELETE FROM models WHERE name = '" + modelName + "'";
        try (Statement stmt = connection.createStatement()) {
            stmt.executeUpdate(query);
        }
    }

    public void addModel(MathModel model) throws SQLException {
        String sql = "INSERT INTO models(name, parameters, timestamp) VALUES(?,?,?)";
        try (PreparedStatement pstmt = connection.prepareStatement(sql)) {
            pstmt.setString(1, model.name);
            pstmt.setString(2, model.parameters);
            pstmt.setTimestamp(3, model.timestamp);
            pstmt.executeUpdate();
        }
    }

    public List<MathModel> getAllModels() throws SQLException {
        List<MathModel> models = new ArrayList<>();
        String sql = "SELECT * FROM models";
        try (PreparedStatement pstmt = connection.prepareStatement(sql);
             ResultSet rs = pstmt.executeQuery()) {
            while (rs.next()) {
                models.add(new MathModel(
                    rs.getString("name"),
                    rs.getString("parameters")
                ));
            }
        }
        return models;
    }
}

// 演示类
public class SimulationApp {
    public static void main(String[] args) {
        try {
            MathModelDAO dao = new MathModelDAO();
            
            // 添加测试数据
            dao.addModel(new MathModel("ModelA", "{a=1,b=2,c=3}" ));
            dao.addModel(new MathModel("ModelB", "{x=10,y=20}" ));
            
            // 模拟用户输入
            String userInput = "ModelA'; DROP TABLE models;--";
            
            // 触发SQL注入漏洞
            System.out.println("[+] 开始删除模型: " + userInput);
            dao.deleteModel(userInput);
            
            // 检查结果
            System.out.println("[+] 删除后剩余模型:");
            for (MathModel m : dao.getAllModels()) {
                System.out.println(m.getClass().getName());
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}