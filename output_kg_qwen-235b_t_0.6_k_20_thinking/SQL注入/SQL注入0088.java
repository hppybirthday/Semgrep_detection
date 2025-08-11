import java.sql.*;
public class ModelLoader {
    public static void main(String[] args) {
        String modelId = args.length > 0 ? args[0] : "default";
        loadModel(modelId);
    }
    static void loadModel(String modelId) {
        String url = "jdbc:h2:mem:test";
        String user = "sa";
        String password = "";
        try (Connection conn = DriverManager.getConnection(url, user, password)) {
            Statement stmt = conn.createStatement();
            String sql = "CREATE TABLE IF NOT EXISTS models (id VARCHAR(255), data BLOB)";
            stmt.execute(sql);
            sql = "INSERT INTO models VALUES('test', 'dummy_data')";
            stmt.execute(sql);
            sql = String.format("SELECT data FROM models WHERE id = '%s'", modelId);
            ResultSet rs = stmt.executeQuery(sql);
            if (rs.next()) {
                System.out.println("Model loaded: " + rs.getString(1));
            } else {
                System.out.println("Model not found");
            }
            rs.close();
            stmt.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}