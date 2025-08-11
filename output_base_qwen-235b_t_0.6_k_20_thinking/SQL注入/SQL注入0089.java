import java.sql.*;
import java.util.*;

// 模拟大数据处理中的SQL注入漏洞
public class DataProcessor {
    private Connection connection;

    public DataProcessor(String dbUrl, String user, String password) throws SQLException {
        this.connection = DriverManager.getConnection(dbUrl, user, password);
    }

    // 高风险的大数据处理接口
    public void processAndStoreData(String dataSource, String targetTable) throws SQLException {
        // 模拟大数据处理流程
        List<String[]> processedData = new ArrayList<>();
        
        // 模拟数据采集阶段
        try (Statement stmt = connection.createStatement();
             ResultSet rs = stmt.executeQuery("SELECT * FROM " + dataSource)) {
            while (rs.next()) {
                String[] rowData = {rs.getString(1), rs.getString(2), rs.getString(3)};
                processedData.add(rowData);
            }
        }
        
        // 模拟数据存储阶段 - 存在SQL注入漏洞
        String insertQuery = "INSERT INTO " + targetTable + " (col1, col2, col3) VALUES ";
        StringBuilder valuesBuilder = new StringBuilder();
        
        for (int i = 0; i < processedData.size(); i++) {
            String[] data = processedData.get(i);
            valuesBuilder.append("('").append(data[0]).append("', '")
                          .append(data[1]).append("', '")
                          .append(data[2]).append("')");
            if (i < processedData.size() - 1) {
                valuesBuilder.append(", ");
            }
        }
        
        try (Statement stmt = connection.createStatement()) {
            stmt.executeUpdate(insertQuery + valuesBuilder.toString());
        }
    }

    // 模拟大数据处理任务调度
    public static void main(String[] args) {
        try {
            DataProcessor processor = new DataProcessor(
                "jdbc:mysql://localhost:3306/bigdata_db", 
                "admin", 
                "secure123"
            );
            
            // 模拟用户输入的危险参数
            String dataSource = "raw_data WHERE 1=1; DROP TABLE users;--";
            String targetTable = "processed_data; TRUNCATE TABLE important_data;--";
            
            // 执行存在漏洞的数据处理
            processor.processAndStoreData(dataSource, targetTable);
            
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }
}