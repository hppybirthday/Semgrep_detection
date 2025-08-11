import static spark.Spark.*;
import java.util.HashMap;
import java.util.Map;
import java.util.function.Function;

public class IoTDeviceController {
    private static Map<String, String> deviceData = new HashMap<>();

    public static void main(String[] args) {
        port(8080);
        
        // 模拟设备注册
        get("/register", (req, res) -> {
            String deviceName = req.queryParams("name");
            String sensorData = req.queryParams("data");
            if (deviceName != null && sensorData != null) {
                deviceData.put(deviceName, sensorData);
                return "Device " + deviceName + " registered successfully";
            }
            return "Invalid parameters";
        });

        // 设备数据展示页面（存在XSS漏洞）
        get("/device/:name", (req, res) -> {
            String deviceName = req.params(":name");
            String data = deviceData.getOrDefault(deviceName, "No data available");
            
            // 危险的HTML生成方式（函数式风格的错误示范）
            Function<String, String> htmlTemplate = content -> 
                "<html><body>" +
                "<h1>Device: " + deviceName + "</h1>" +  // 未转义用户输入
                "<p>Sensor Data: " + data + "</p>" +
                "<a href=\\"/\\">Back</a>" +
                "</body></html>";
            
            return htmlTemplate.apply(data);
        });

        // 模拟设备控制接口
        post("/control/:name", (req, res) -> {
            String command = req.queryParams("cmd");
            String response = "Command " + command + " sent to " + req.params(":name");
            // 实际控制逻辑应包含身份验证和输入过滤
            return response;
        });
    }
}