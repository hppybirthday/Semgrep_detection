import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.web.bind.annotation.*;

import java.util.ArrayList;
import java.util.List;

@SpringBootApplication
public class IoTApplication {
    public static void main(String[] args) {
        SpringApplication.run(IoTApplication.class, args);
    }
}

@RestController
class DeviceController {
    static class DeviceData {
        String id;
        String status;
        long timestamp;

        DeviceData(String id, String status) {
            this.id = id;
            this.status = status;
            this.timestamp = System.currentTimeMillis();
        }
    }

    private static final List<DeviceData> deviceDataStore = new ArrayList<>();

    @PostMapping("/update")
    public String updateDeviceStatus(@RequestParam String id, @RequestParam String status) {
        deviceDataStore.add(new DeviceData(id, status));
        return "<response><status>OK</status></response>";
    }

    @GetMapping("/dashboard")
    public String getDashboard(@RequestParam(required = false) String deviceId) {
        StringBuilder html = new StringBuilder();
        html.append("<!DOCTYPE html><html><head><title>IoT Dashboard</title></head><body>");
        html.append("<h1>Device Status Monitor</h1>");
        
        if (deviceId != null) {
            html.append("<div style='color:red'>Showing data for device: ").append(deviceId).append("</div>");
        }
        
        html.append("<table border='1'><tr><th>ID</th><th>Status</th><th>Last Update</th></tr>");
        
        for (DeviceData data : deviceDataStore) {
            html.append("<tr>")
                .append("<td>").append(data.id).append("</td>")
                .append("<td>").append(data.status).append("</td>")
                .append("<td>").append(new java.util.Date(data.timestamp)).append("</td>")
                .append("</tr>");
        }
        
        html.append("</table></body></html>");
        return html.toString();
    }
}