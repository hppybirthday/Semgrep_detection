import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.*;
import java.util.*;

@SpringBootApplication
public class IotDeviceApp {
    static List<Device> devices = new ArrayList<>();

    public static void main(String[] args) {
        SpringApplication.run(IotDeviceApp.class, args);
    }

    @Controller
    class DeviceController {
        @GetMapping("/devices")
        public String listDevices(Map<String, Object> model) {
            model.put("devices", devices);
            return "devices";
        }

        @PostMapping("/addDevice")
        public String addDevice(@RequestParam String name, @RequestParam String location) {
            devices.add(new Device(name, location));
            return "redirect:/devices";
        }

        // 模拟设备数据展示页面
        @GetMapping("/device/{index}")
        public String showDevice(@PathVariable int index, Map<String, Object> model) {
            if (index >= 0 && index < devices.size()) {
                Device device = devices.get(index);
                // 漏洞点：直接将用户输入拼接到JavaScript上下文中
                String jsCode = String.format("var deviceName = '%s'; console.log('Device: ' + deviceName);", 
                    device.getName());
                model.put("jsCode", jsCode);
                return "deviceDetail";
            }
            return "error";
        }
    }

    static class Device {
        private String name;
        private String location;

        Device(String name, String location) {
            this.name = name;
            this.location = location;
        }

        public String getName() { return name; }
        public String getLocation() { return location; }
    }
}

// JSP视图 devices.jsp
// <html><body>
// <h2>设备列表</h2>
// <ul>
// <c:forEach items="${devices}" var="device" varStatus="status">
//   <li><a href="/device/${status.index}">${device.name}</a> - ${device.location}</li>
// </c:forEach>
// </ul>
// </body></html>

// deviceDetail.jsp
// <html><body>
// <h2>设备详情</h2>
// <script type="text/javascript">
// ${jsCode}  // 漏洞触发点：未对用户输入进行转义
// </script>
// </body></html>