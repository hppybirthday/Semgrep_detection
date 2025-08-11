import java.io.*;
import java.nio.file.*;
import java.util.*;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/device")
public class IoTDeviceController {
    private final DeviceService deviceService = new DeviceService();

    @GetMapping("/logs")
    public String getLogFileContent(@RequestParam String deviceId, @RequestParam String fileName) {
        try {
            return deviceService.readLogFile(deviceId, fileName);
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }
}

class DeviceService {
    private static final String BASE_DIR = "/var/iot_data/";

    public String readLogFile(String deviceId, String fileName) throws IOException {
        // 漏洞点：直接拼接用户输入
        Path filePath = Paths.get(BASE_DIR + deviceId + "/logs/" + fileName);
        
        // 危险验证：仅检查文件存在性，未规范路径
        if (!filePath.toString().startsWith(BASE_DIR)) {
            throw new SecurityException("Invalid path");
        }
        
        if (!Files.exists(filePath)) {
            throw new FileNotFoundException("File not found");
        }

        // 实际读取操作
        StringBuilder content = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(filePath.toFile()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                content.append(line).append("\
");
            }
        }
        return content.toString();
    }

    // 模拟设备数据目录初始化
    public DeviceService() {
        try {
            Files.createDirectories(Paths.get(BASE_DIR + "D12345/logs/"));
            Files.write(Paths.get(BASE_DIR + "D12345/logs/sample.log"), "[INFO] Device started\
[DEBUG] Memory usage: 45%".getBytes());
            
            // 模拟敏感文件（实际应被保护）
            Files.createDirectories(Paths.get(BASE_DIR + "../etc/"));
            Files.write(Paths.get(BASE_DIR + "../etc/passwd"), "root:x:0:0:root:/root:/bin/bash".getBytes());
            
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}