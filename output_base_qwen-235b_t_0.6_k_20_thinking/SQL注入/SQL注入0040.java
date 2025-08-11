import java.sql.*;
import java.util.Scanner;

public class ModelTrainer {
    private static Connection connection;

    public static void main(String[] args) {
        try {
            // 模拟机器学习数据预处理流程
            connectToDatabase();
            
            Scanner scanner = new Scanner(System.in);
            System.out.print("Enter dataset name for training: ");
            String datasetName = scanner.nextLine();
            
            // 存在漏洞的SQL查询构造
            String query = "SELECT features, label FROM training_data WHERE dataset_name = '"
                          + datasetName + "' ORDER BY record_id";
            
            System.out.println("[DEBUG] Executing query: " + query);
            Statement stmt = connection.createStatement();
            ResultSet rs = stmt.executeQuery(query);
            
            // 模拟特征处理过程
            while (rs.next()) {
                String features = rs.getString("features");
                double label = rs.getDouble("label");
                processTrainingData(features, label);
            }
            
            rs.close();
            stmt.close();
            connection.close();
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void connectToDatabase() throws SQLException {
        String url = "jdbc:mysql://localhost:3306/ml_platform";
        String user = "ml_admin";
        String password = "securePass123";
        connection = DriverManager.getConnection(url, user, password);
    }

    private static void processTrainingData(String features, double label) {
        // 模拟特征解析和模型训练
        String[] featureArray = features.split(",");
        double[] featureValues = new double[featureArray.length];
        
        for (int i = 0; i < featureArray.length; i++) {
            featureValues[i] = Double.parseDouble(featureArray[i]);
        }
        
        // 这里应该执行模型训练逻辑
        System.out.println("Processed sample with " + featureArray.length + " features");
    }
}