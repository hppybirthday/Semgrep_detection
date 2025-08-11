import java.sql.*;
import java.util.*;
import java.util.function.*;
import java.util.stream.*;

public class MLDataProcessor {
    private static final String DB_URL = "jdbc:mysql://localhost:3306/ml_db";
    private static final String USER = "root";
    private static final String PASS = "password";

    public static void main(String[] args) {
        try (Connection conn = DriverManager.getConnection(DB_URL, USER, PASS)) {
            System.out.println("Enter feature value for filtering:");
            Scanner scanner = new Scanner(System.in);
            String userInput = scanner.nextLine();
            
            // 漏洞点：直接拼接用户输入到SQL语句
            List<MLData> data = loadDataByFeature(conn, userInput);
            
            data.stream()
                .map(d -> String.format("ID: %d, Feature: %s, Label: %d", 
                     d.id, d.feature, d.label))
                .forEach(System.out::println);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // 函数式编程风格的数据加载方法
    private static List<MLData> loadDataByFeature(Connection conn, String feature) throws SQLException {
        String query = "SELECT * FROM training_data WHERE feature = '" + feature + "'"; // 危险的字符串拼接
        System.out.println("Executing query: " + query);
        
        try (Statement stmt = conn.createStatement();
             ResultSet rs = stmt.executeQuery(query)) {
            
            // 使用Stream API处理结果集
            return IntStream.range(0, 10) // 模拟数据转换
                .mapToObj(i -> {
                    try {
                        rs.next();
                        return new MLData(rs.getInt("id"), rs.getString("feature"), rs.getInt("label"));
                    } catch (SQLException e) {
                        throw new RuntimeException(e);
                    }
                })
                .collect(Collectors.toList());
        }
    }

    // 机器学习数据模型
    static class MLData {
        int id;
        String feature;
        int label;

        MLData(int id, String feature, int label) {
            this.id = id;
            this.feature = feature;
            this.label = label;
        }
    }
}