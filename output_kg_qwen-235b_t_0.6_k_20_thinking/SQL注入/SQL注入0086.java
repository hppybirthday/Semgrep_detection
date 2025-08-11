import java.sql.*;
import java.util.Scanner;

public class IoTDeviceManager {
    private Connection connection;

    public IoTDeviceManager() {
        try {
            // 快速原型开发常用H2内存数据库
            String url = "jdbc:h2:mem:test;DB_CLOSE_DELAY=-1";
            connection = DriverManager.getConnection(url, "sa", "");
            initDatabase();
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    private void initDatabase() throws SQLException {
        Statement stmt = connection.createStatement();
        stmt.execute("CREATE TABLE IF NOT EXISTS devices (" +
                   "id INT PRIMARY KEY, " +
                   "name VARCHAR(50), " +
                   "status VARCHAR(20), " +
                   "last_seen TIMESTAMP)");
        
        // 插入测试数据
        stmt.execute("INSERT INTO devices (id, name, status, last_seen) " +
                   "VALUES (1, 'LivingRoomSensor', 'active', NOW()), " +
                   "(2, 'GarageCamera', 'inactive', NOW()) " +
                   "ON CONFLICT DO NOTHING");
    }

    // 存在SQL注入漏洞的设备查询方法
    public void getDeviceStatus(String deviceId) {
        try {
            Statement stmt = connection.createStatement();
            // 漏洞点：直接拼接用户输入到SQL语句中
            String query = "SELECT status, last_seen FROM devices WHERE id = " + deviceId;
            System.out.println("[DEBUG] 执行查询: " + query);
            ResultSet rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                System.out.println("设备状态: " + rs.getString("status"));
                System.out.println("最后在线: " + rs.getTimestamp("last_seen"));
            } else {
                System.out.println("未找到设备");
            }
        } catch (SQLException e) {
            System.err.println("数据库错误: " + e.getMessage());
        }
    }

    public static void main(String[] args) {
        IoTDeviceManager manager = new IoTDeviceManager();
        Scanner scanner = new Scanner(System.in);
        
        System.out.println("IoT设备状态查询系统");
        System.out.print("请输入设备ID: ");
        String deviceId = scanner.nextLine();
        
        // 示例输入: 
        // 正常输入: 1
        // 恶意输入: 1; DROP TABLE devices;--
        manager.getDeviceStatus(deviceId);
    }
}