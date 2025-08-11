import java.sql.*;
import java.util.*;

// 高抽象建模：数据处理管道接口
interface DataProcessor {
    List<Map<String, String>> process(String rawData);
}

// CSV数据解析器实现
class CsvDataProcessor implements DataProcessor {
    public List<Map<String, String>> process(String csvData) {
        List<Map<String, String>> records = new ArrayList<>();
        String[] lines = csvData.split("\\\
");
        
        // 模拟CSV解析（实际应使用专业库）
        for (String line : lines) {
            String[] fields = line.split(",");
            Map<String, String> record = new HashMap<>();
            record.put("id", fields[0]);
            record.put("value", fields[1]);
            records.add(record);
        }
        return records;
    }
}

// 数据存储服务（存在漏洞的核心组件）
class DataStorage {
    private Connection connection;

    public DataStorage(String dbUrl) throws SQLException {
        this.connection = DriverManager.getConnection(dbUrl);
    }

    // 危险的数据存储方法
    public void storeData(List<Map<String, String>> dataRecords) throws SQLException {
        Statement stmt = connection.createStatement();
        for (Map<String, String> record : dataRecords) {
            // 漏洞点：直接拼接SQL语句（错误示范）
            String sql = "INSERT INTO data_table (id, value) VALUES ('" 
                       + record.get("id") + "', '" 
                       + record.get("value") + "')";
            stmt.addBatch(sql);
        }
        stmt.executeBatch();
    }
}

// 主处理类
public class DataPipeline {
    public static void main(String[] args) {
        String csvInput = "1,normal_data\
2,evil_data'); DROP TABLE data_table;--";
        
        try {
            // 初始化组件
            DataProcessor processor = new CsvDataProcessor();
            DataStorage storage = new DataStorage("jdbc:mysql://localhost:3306/test_db");
            
            // 执行数据处理管道
            List<Map<String, String>> processedData = processor.process(csvInput);
            storage.storeData(processedData);
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}