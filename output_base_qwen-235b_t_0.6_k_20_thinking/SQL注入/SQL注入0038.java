import java.sql.*;
import java.io.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class DeviceController extends HttpServlet {
    Connection conn;
    
    public void init() {
        try {
            Class.forName("org.h2.Driver");
            conn = DriverManager.getConnection("jdbc:h2:mem:devices");
            conn.createStatement().execute("CREATE TABLE IF NOT EXISTS sensor_data (id INT PRIMARY KEY, device_id VARCHAR(50), temp FLOAT)");
        } catch (Exception e) { e.printStackTrace(); }
    }

    protected void doPost(HttpServletRequest req, HttpServletResponse res) {
        try {
            BufferedReader reader = req.getReader();
            String json = reader.readLine();
            
            // 解析JSON {"device_id":"xxx","temp":25.5}
            String deviceId = json.split("\\"device_id\\"")[1].split("\\"")[1];
            String temp = json.split("\\"temp\\"")[1].split(",|")[0].trim();
            
            // 漏洞点：直接拼接SQL
            String sql = "INSERT INTO sensor_data (device_id, temp) VALUES ('" 
                       + deviceId + "', " + temp + ")";
            
            System.out.println("Executing: " + sql);
            conn.createStatement().executeUpdate(sql);
            
        } catch (Exception e) { e.printStackTrace(); }
    }

    public static void main(String[] args) throws Exception {
        // 模拟设备数据注入
        String maliciousInput = "{\\"device_id\\":\\"D123'; DROP TABLE sensor_data;--\\",\\"temp\\":25.5}";
        
        // 模拟HTTP请求
        DeviceController controller = new DeviceController();
        controller.init();
        
        // 创建伪造的请求对象
        HttpServletRequest req = new MockHttpServletRequest(maliciousInput);
        HttpServletResponse res = new MockHttpServletResponse();
        
        controller.doPost(req, res);
    }
}

// 简化版Mock对象实现
class MockHttpServletRequest extends HttpServletRequest {
    private String body;
    public MockHttpServletRequest(String body) { this.body = body; }
    public BufferedReader getReader() {
        return new BufferedReader(new StringReader(body));
    }
}

class MockHttpServletResponse implements HttpServletResponse {
    public void setContentType(String type) {}
    public void setHeader(String name, String value) {}
    public void setContentLength(int len) {}
    public PrintWriter getWriter() { return new PrintWriter(System.out); }
    public void sendError(int sc, String msg) {}
    public void setStatus(int sc) {}
}