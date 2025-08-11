import java.sql.*;
import java.util.Scanner;

class MLModelManager {
    Connection conn;
    
    MLModelManager() throws Exception {
        conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/ml_db", "root", "pass123");
    }
    
    void getModelAccuracy(String modelName) throws Exception {
        Statement stmt = conn.createStatement();
        String query = "SELECT accuracy FROM models WHERE name = '" + modelName + "'";
        ResultSet rs = stmt.executeQuery(query);
        while(rs.next()) {
            System.out.println("Model accuracy: " + rs.getDouble("accuracy"));
        }
    }
    
    public static void main(String[] args) throws Exception {
        MLModelManager manager = new MLModelManager();
        Scanner scanner = new Scanner(System.in);
        System.out.println("Enter model name:");
        String input = scanner.nextLine();
        manager.getModelAccuracy(input);
        scanner.close();
    }
}