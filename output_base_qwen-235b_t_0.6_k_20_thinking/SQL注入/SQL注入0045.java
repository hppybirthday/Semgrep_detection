import java.sql.*;
import java.util.*;

public class ModelSimulator {
    static {
        try {
            Class.forName("com.mysql.cj.jdbc.Driver");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) throws Exception {
        Connection conn = DriverManager.getConnection(
            "jdbc:mysql://localhost:3306/models", "user", "password");
        
        // 模拟数学建模参数输入
        Map<String, String> params = new HashMap<>();
        params.put("model_name", "heat_diffusion");
        params.put("param_name", "temperature\");
        params.put("value", "42; DROP TABLE simulation_data;--");
        
        saveModelParameter(conn, params);
        conn.close();
    }

    public static void saveModelParameter(Connection conn, Map<String, String> params) throws Exception {
        String query = "INSERT INTO model_params (model_name, param_name, value) VALUES '" 
            + params.get("model_name") + "', '" 
            + params.get("param_name") + "', '" 
            + params.get("value") + "')";
        
        // 使用Statement而非PreparedStatement导致SQL注入漏洞
        Statement stmt = conn.createStatement();
        System.out.println("Executing query: " + query);
        stmt.executeUpdate(query);
    }

    // 动态生成模型参数查询的元编程示例
    public static ResultSet queryModelData(Connection conn, String condition) throws Exception {
        String sql = "SELECT * FROM simulation_data WHERE " + condition;
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}