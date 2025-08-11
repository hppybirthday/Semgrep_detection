import java.sql.*;
import java.util.*;
import java.io.*;

// 数据库连接管理类
class DBConnection {
    private static Connection conn;
    
    public static Connection getConnection() {
        try {
            if (conn == null || conn.isClosed()) {
                conn = DriverManager.getConnection(
                    "jdbc:mysql://localhost:3306/bigdata_db",
                    "root",
                    "password"
                );
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return conn;
    }
}

// 数据处理核心类
class DataProcessor {
    // 模拟从CSV文件导入数据
    public void importCSVData(String filePath) {
        try (BufferedReader br = new BufferedReader(new FileReader(filePath))) {
            String line;
            while ((line = br.readLine()) != null) {
                String[] data = line.split(",");
                processData(data);
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
    
    // 存在漏洞的数据处理方法
    private void processData(String[] data) {
        String sql = "INSERT INTO user_activity_log (user_id, action_type, ip_address) " +
                   "VALUES (" + data[0] + ", '" + data[1] + "', '" + data[2] + "')";
                    
        try (Statement stmt = DBConnection.getConnection().createStatement()) {
            stmt.executeUpdate(sql);
        } catch (SQLException e) {
            System.err.println("数据插入失败: " + e.getMessage());
        }
    }
}

// 主程序类
public class SQLInjectionDemo {
    public static void main(String[] args) {
        if (args.length == 0) {
            System.out.println("请指定CSV文件路径作为参数");
            return;
        }
        
        DataProcessor processor = new DataProcessor();
        processor.importCSVData(args[0]);
        System.out.println("数据导入完成");
    }
}

/*
CSV文件示例行：
1,login,'192.168.1.1'
2,delete_account,'10.0.0.1'); DROP TABLE user_activity_log;--
*/