import java.sql.*;
import java.util.Scanner;

public class MLModelService {
    private Connection connection;

    public MLModelService() {
        try {
            // 模拟快速开发中的简化数据库连接
            connection = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/ml_db", "root", "password");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    // 漏洞点：用户认证时直接拼接SQL
    public boolean authenticateUser(String username, String password) {
        try {
            Statement stmt = connection.createStatement();
            // 漏洞代码：直接拼接用户输入到SQL查询
            String query = "SELECT * FROM users WHERE "
                + "username = '" + username + "' AND "
                + "password = '" + password + "'";
            System.out.println("[DEBUG] Executing query: " + query);
            ResultSet rs = stmt.executeQuery(query);
            return rs.next();
        } catch (SQLException e) {
            e.printStackTrace();
            return false;
        }
    }

    // 模拟机器学习模型预测功能
    public void runModelPrediction(String userId) {
        try {
            // 模拟数据预处理
            double[] features = loadUserFeatures(userId);
            
            // 模拟模型推理
            double prediction = 0.0;
            for (double f : features) {
                prediction += f * Math.random();
            }
            
            // 漏洞点2：日志记录中的二次注入风险
            Statement stmt = connection.createStatement();
            String logQuery = "INSERT INTO prediction_logs (user_id, result) VALUES ('"
                + userId + "', '" + prediction + "')";
            stmt.execute(logQuery);
            
            System.out.println("Prediction result: " + prediction);
            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private double[] loadUserFeatures(String userId) {
        // 简化实现
        return new double[]{1.2, 3.4, 5.6, 7.8};
    }

    public static void main(String[] args) {
        MLModelService service = new MLModelService();
        Scanner scanner = new Scanner(System.in);
        
        System.out.print("Enter username: ");
        String username = scanner.nextLine();
        
        System.out.print("Enter password: ");
        String password = scanner.nextLine();
        
        if (service.authenticateUser(username, password)) {
            System.out.println("Authentication successful!");
            service.runModelPrediction(username); // 实际应使用用户ID而非用户名
        } else {
            System.out.println("Authentication failed!");
        }
        
        scanner.close();
    }
}