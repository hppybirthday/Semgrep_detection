import java.sql.*;
import java.util.*;

public class MLModel {
    Connection conn;
    
    MLModel() throws Exception {
        conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/ml_db", "root", "pass");
    }
    
    ResultSet loadData(String feature) throws Exception {
        Statement stmt = conn.createStatement();
        String query = "SELECT id,features,label FROM training_data WHERE feature_name = '" + feature + "'";
        return stmt.executeQuery(query);
    }
    
    void trainModel(String targetFeature) {
        try {
            ResultSet rs = loadData(targetFeature);
            List<double[]> data = new ArrayList<>();
            List<Integer> labels = new ArrayList<>();
            
            while (rs.next()) {
                data.add(Arrays.stream(rs.getString("features").split(",")).mapToDouble(Double::parseDouble).toArray());
                labels.add(rs.getInt("label"));
            }
            
            System.out.println("Training model with " + data.size() + " samples...");
            // 模型训练逻辑（此处省略）
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    public static void main(String[] args) {
        try {
            MLModel model = new MLModel();
            Scanner sc = new Scanner(System.in);
            System.out.print("Enter feature name to train: ");
            String input = sc.nextLine();
            model.trainModel(input);
        } catch (Exception e) {
            System.out.println("Training failed: " + e.getMessage());
        }
    }
}