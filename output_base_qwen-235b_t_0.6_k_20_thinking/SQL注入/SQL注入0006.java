import java.sql.*;
import java.util.Scanner;

public class IoTDeviceManager {
    private static Connection connection;

    public static void main(String[] args) {
        try {
            // 模拟数据库连接
            String url = "jdbc:mysql://localhost:3306/iot_system";
            String user = "root";
            String password = "admin123";
            connection = DriverManager.getConnection(url, user, password);
            
            // 模拟设备登录接口
            Scanner scanner = new Scanner(System.in);
            System.out.println("=== IoT设备认证系统 ===");
            System.out.print("设备ID: ");
            String deviceId = scanner.nextLine();
            System.out.print("密码: ");
            String authPassword = scanner.nextLine();
            
            // 存在漏洞的SQL查询
            String query = "SELECT * FROM devices WHERE device_id = '" 
                          + deviceId + "' AND password = '" + authPassword + "'";
            
            // 执行查询
            Statement statement = connection.createStatement();
            ResultSet resultSet = statement.executeQuery(query);
            
            // 处理认证结果
            if (resultSet.next()) {
                System.out.println("[+] 认证成功");
                System.out.println("设备状态: " + resultSet.getString("status"));
                System.out.println("最后在线时间: " + resultSet.getString("last_seen"));
                // 模拟数据采集接口
                collectSensorData(deviceId);
            } else {
                System.out.println("[-] 认证失败");
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static void collectSensorData(String deviceId) throws SQLException {
        // 模拟传感器数据采集
        String dataQuery = "SELECT * FROM sensor_data WHERE device_id = '" 
                         + deviceId + "' ORDER BY timestamp DESC LIMIT 10";
        Statement statement = connection.createStatement();
        ResultSet rs = statement.executeQuery(dataQuery);
        
        System.out.println("\
[最近传感器数据]");
        while (rs.next()) {
            System.out.println("温度: " + rs.getDouble("temperature") + ", " +
                              "湿度: " + rs.getDouble("humidity") + ", " +
                              "时间: " + rs.getString("timestamp"));
        }
    }
}