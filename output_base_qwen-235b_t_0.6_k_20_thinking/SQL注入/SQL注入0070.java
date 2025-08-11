import java.sql.*;
import java.util.Scanner;

public class IoTDeviceManager {
    public static void main(String[] args) {
        Connection conn = null;
        Statement stmt = null;
        ResultSet rs = null;
        
        try {
            // 模拟IoT设备数据库连接
            conn = DriverManager.getConnection(
                "jdbc:mysql://localhost:3306/iot_system", "root", "password");
            
            Scanner scanner = new Scanner(System.in);
            System.out.print("请输入设备ID: ");
            String deviceId = scanner.nextLine();
            System.out.print("请输入设备密码: ");
            String password = scanner.nextLine();
            
            // 模拟设备认证过程（存在漏洞）
            String query = "SELECT * FROM devices WHERE id = '" + deviceId 
                          + "' AND password = '" + password + "'";
            stmt = conn.createStatement();
            rs = stmt.executeQuery(query);
            
            if (rs.next()) {
                System.out.println("认证成功！设备信息：");
                System.out.println("设备ID: " + rs.getString("id"));
                System.out.println("设备类型: " + rs.getString("type"));
                System.out.println("最后在线时间: " + rs.getTimestamp("last_online"));
                
                // 模拟数据采集操作
                System.out.print("请输入采集间隔(秒): ");
                int interval = scanner.nextInt();
                String dataQuery = "SELECT * FROM sensor_data WHERE device_id = '" 
                                 + deviceId + "' ORDER BY timestamp DESC LIMIT " 
                                 + (interval * 10);
                Statement dataStmt = conn.createStatement();
                ResultSet dataRs = dataStmt.executeQuery(dataQuery);
                
                while (dataRs.next()) {
                    System.out.println("数据: " + dataRs.getString("value") 
                                    + " 时间: " + dataRs.getTimestamp("timestamp"));
                }
            } else {
                System.out.println("认证失败！");
            }
            
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            // 关闭资源
            try { if (rs != null) rs.close(); } catch (Exception e) {}
            try { if (stmt != null) stmt.close(); } catch (Exception e) {}
            try { if (conn != null) conn.close(); } catch (Exception e) {}
        }
    }
}