import java.io.*;
import java.util.*;
import java.util.function.*;
import javax.servlet.*;
import javax.servlet.http.*;

public class DeviceControlServlet extends HttpServlet {
    private final Map<String, String> deviceDatabase = new HashMap<>();

    public DeviceControlServlet() {
        // 模拟初始化设备数据
        deviceDatabase.put("001", "Living Room Thermostat");
        deviceDatabase.put("002", "Kitchen Humidity Sensor");
    }

    @Override
    protected void doGet(HttpServletRequest req, HttpServletResponse res) 
        throws IOException, ServletException {
        
        res.setContentType("text/html");
        PrintWriter out = res.getWriter();
        
        // 获取设备ID参数（存在漏洞的输入点）
        String deviceId = Optional.ofNullable(req.getParameter("id"))
            .filter(s -> !s.isEmpty())
            .orElse("default");
        
        // 模拟设备数据获取
        String deviceName = deviceDatabase.getOrDefault(deviceId, "Unknown Device");
        
        // 生成设备状态页面（存在XSS漏洞）
        String html = String.format("""
            <html>
                <body>
                    <h1>%s Status</h1>
                    <p>Current Value: <span id="sensorValue">%s</span></p>
                    <script>
                        // 恶意脚本可通过设备名称注入
                        document.getElementById('sensorValue').innerHTML = 
                            '%s'; // 模拟传感器数据更新
                    </script>
                </body>
            </html>
        """, deviceName, getRandomSensorValue(), getScriptInjection(deviceId));
        
        out.println(html);
    }

    // 模拟随机传感器数据生成
    private String getRandomSensorValue() {
        return String.format("%.2f%%", Math.random() * 100);
    }

    // 存在漏洞的脚本注入点（演示攻击路径）
    private String getScriptInjection(String deviceId) {
        return "<script>" + 
            "document.write('XSS Attack!');" + 
            "alert('Cookie Theft: '+document.cookie);" + 
            "</script>".contains(deviceId) ? deviceId : "";
    }

    // 函数式接口示例
    private final BiFunction<String, Integer, String> dataFormatter = 
        (value, precision) -> String.format("%%.%df", precision).formatted(Double.parseDouble(value));
}