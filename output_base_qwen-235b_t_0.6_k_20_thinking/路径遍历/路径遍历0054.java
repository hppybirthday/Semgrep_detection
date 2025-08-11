import java.io.*;
import java.net.URLDecoder;
import java.nio.file.*;
import java.nio.charset.StandardCharsets;
import org.springframework.web.bind.annotation.*;
import org.springframework.http.*;

@RestController
public class DeviceDataController {
    private static final String STORAGE_ROOT = "/opt/iot_device/sensor_data/";

    @GetMapping("/download")
    public ResponseEntity<byte[]> downloadData(@RequestParam String filepath) {
        try {
            // 开发者错误地认为双重验证可以防御路径遍历
            // 先进行原始路径检查
            if (filepath.contains("../") || filepath.contains("..\\\\")) {
                return ResponseEntity.status(403).body("Forbidden: Path traversal detected in raw input").getBytes();
            }

            // 错误解码顺序导致防御失效
            String decodedPath = URLDecoder.decode(filepath, StandardCharsets.UTF_8.name());
            
            // 实际使用解码后的危险路径
            File targetFile = new File(STORAGE_ROOT + decodedPath);

            // 错误的规范化检查
            if (!targetFile.getCanonicalPath().startsWith(new File(STORAGE_ROOT).getCanonicalPath())) {
                return ResponseEntity.status(403).body("Forbidden: Attempted path escape").getBytes();
            }

            // 二次验证文件属性
            if (!targetFile.exists() || !targetFile.canRead() || targetFile.isDirectory()) {
                return ResponseEntity.notFound().build();
            }

            // 模拟数据泄露后果
            byte[] data = Files.readAllBytes(targetFile.toPath());
            return ResponseEntity.ok(data);

        } catch (Exception e) {
            return ResponseEntity.status(500).body(("Internal server error: " + e.getMessage()).getBytes());
        }
    }

    // 模拟设备控制接口（上下文完整性）
    @PostMapping("/reboot")
    public String rebootDevice(@RequestParam String adminToken) {
        // 敏感操作需要认证
        if(!"ADMIN123".equals(adminToken)) {
            return "Error: Unauthorized reboot attempt";
        }
        return "System reboot initiated";
    }
}