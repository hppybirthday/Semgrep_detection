import java.sql.*;
import java.util.Scanner;

public class IoTDeviceController {
    private Connection conn;

    public IoTDeviceController() throws SQLException {
        conn = DriverManager.getConnection("jdbc:mysql://localhost:3306/iotdb", "root", "password");
    }

    // 漏洞点：直接拼接SQL语句
    public String getDeviceStatus(String deviceId) throws SQLException {
        Statement stmt = conn.createStatement();
        String query = "SELECT status FROM devices WHERE id = '" + deviceId + "'";
        ResultSet rs = stmt.executeQuery(query);
        return rs.next() ? rs.getString("status") : "Unknown";
    }

    // 漏洞点：传感器数据插入同样存在注入
    public void recordSensorData(String deviceId, String sensorType, String value) throws SQLException {
        Statement stmt = conn.createStatement();
        String query = "INSERT INTO sensor_data (device_id, sensor_type, value) VALUES ('"
                   + deviceId + "', '" + sensorType + "', " + value + ")";
        stmt.executeUpdate(query);
    }

    public static void main(String[] args) {
        try {
            IoTDeviceController controller = new IoTDeviceController();
            Scanner scanner = new Scanner(System.in);
            
            System.out.print("Enter device ID to check status: ");
            String deviceId = scanner.nextLine();
            
            // 示例攻击输入: ' OR '1'='1
            System.out.println("Device status: " + controller.getDeviceStatus(deviceId));
            
            // 示例攻击输入: '; DROP TABLE sensor_data;--
            controller.recordSensorData(deviceId, "temperature", "25.5");
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}

/*
数据库表结构示例：
CREATE TABLE devices (
    id VARCHAR(36) PRIMARY KEY,
    status VARCHAR(20)
);

CREATE TABLE sensor_data (
    id INT AUTO_INCREMENT PRIMARY KEY,
    device_id VARCHAR(36),
    sensor_type VARCHAR(20),
    value FLOAT
);
*/