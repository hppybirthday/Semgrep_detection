import org.springframework.web.bind.annotation.*;
import org.springframework.data.redis.core.RedisTemplate;
import com.alibaba.fastjson.JSONObject;
import java.util.List;
import java.util.ArrayList;

@RestController
@RequestMapping("/api")
public class VulnerableController {

    private final RedisTemplate<String, String> redisTemplate;

    public VulnerableController(RedisTemplate<String, String> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    @GetMapping("/status")
    public String checkStatus(@RequestParam String tug_status, @RequestParam String pid) {
        try {
            String statusKey = "device_status:" + tug_status;
            String metadataKey = "metadata:" + pid;
            
            String statusData = redisTemplate.opsForValue().get(statusKey);
            String metadataStr = redisTemplate.opsForValue().get(metadataKey);
            
            if (statusData == null || metadataStr == null) {
                return "Missing data";
            }
            
            // 不安全的反序列化操作（未验证类型）
            List<String> metadata = JSONObject.parseObject(metadataStr, List.class);
            
            if (metadata.contains("admin")) {
                return processAdminRequest(statusData);
            } else {
                return processUserRequest(statusData, metadata.size());
            }
        } catch (Exception e) {
            return "Error processing request";
        }
    }
    
    private String processAdminRequest(String statusData) {
        return "Admin access: " + statusData;
    }
    
    private String processUserRequest(String statusData, int metadataSize) {
        return "User access: " + statusData + ", Metadata size: " + metadataSize;
    }
    
    @PostMapping("/update")
    public String updateMetadata(@RequestBody String body) {
        try {
            // 直接反序列化HTTP请求体（双重攻击面）
            List<String> data = JSONObject.parseObject(body, List.class);
            return "Received data size: " + data.size();
        } catch (Exception e) {
            return "Update failed";
        }
    }
}