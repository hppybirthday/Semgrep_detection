import java.sql.*;
import java.util.Scanner;

public class ModelTrainer {
    private Connection connection;

    public ModelTrainer() {
        try {
            connection = DriverManager.getConnection("jdbc:h2:mem:test", "sa", "");
            createTable();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private void createTable() throws SQLException {
        try (Statement stmt = connection.createStatement()) {
            stmt.execute("CREATE TABLE IF NOT EXISTS models (id INT PRIMARY KEY AUTO_INCREMENT, name VARCHAR(255), params VARCHAR(255))");
        }
    }

    public void saveModel(String modelName, String params) {
        if (modelName == null || params == null) {
            System.out.println("Invalid input");
            return;
        }

        String query = "INSERT INTO models (name, params) VALUES ('" + modelName + "', '" + params + "')";
        
        try (Statement stmt = connection.createStatement()) {
            stmt.executeUpdate(query);
            System.out.println("Model saved successfully");
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public void loadModel(String modelName) {
        if (modelName == null) {
            System.out.println("Invalid input");
            return;
        }

        String query = "SELECT * FROM models WHERE name = '" + modelName + "'";
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            while (rs.next()) {
                System.out.println("Loaded model: " + rs.getString("name"));
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] args) {
        ModelTrainer trainer = new ModelTrainer();
        Scanner scanner = new Scanner(System.in);
        
        System.out.print("Enter model name: ");
        String name = scanner.nextLine();
        
        System.out.print("Enter model parameters: ");
        String params = scanner.nextLine();
        
        trainer.saveModel(name, params);
        trainer.loadModel(name);
    }
}