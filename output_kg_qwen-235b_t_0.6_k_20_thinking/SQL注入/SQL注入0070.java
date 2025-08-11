import java.sql.*;
import java.util.Scanner;

public class IoTDeviceManager {
    private static Connection connection;

    public static void main(String[] args) {
        try {
            // IoT设备管理系统初始化
            connectToDatabase();
            Scanner scanner = new Scanner(System.in);
            
            System.out.println("=== IoT设备数据查询系统 ===");
            System.out.print("请输入设备ID查询传感器数据: ");
            String deviceId = scanner.nextLine();
            
            // 模拟攻击输入: ' OR '1'='1'; DROP TABLE sensor_data; --
            System.out.println("\
查询结果:");
            displaySensorData(deviceId);
            
            connection.close();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void connectToDatabase() throws SQLException {
        String url = "jdbc:mysql://localhost:3306/iot_system";
        String user = "root";
        String password = "admin123";
        connection = DriverManager.getConnection(url, user, password);
        System.out.println("数据库连接已建立");
    }

    private static void displaySensorData(String deviceId) throws SQLException {
        Statement statement = connection.createStatement();
        // 存在漏洞的SQL构造方式
        String query = "SELECT * FROM sensor_data WHERE device_id = '" + deviceId + "'";
        System.out.println("执行查询: " + query);
        ResultSet resultSet = statement.executeQuery(query);
        
        while (resultSet.next()) {
            System.out.printf("设备ID: %s | 温度: %.1f°C | 湿度: %.1f%% | 时间戳: %s\
",
                resultSet.getString("device_id"),
                resultSet.getDouble("temperature"),
                resultSet.getDouble("humidity"),
                resultSet.getTimestamp("timestamp"));
        }
        
        resultSet.close();
        statement.close();
    }
}