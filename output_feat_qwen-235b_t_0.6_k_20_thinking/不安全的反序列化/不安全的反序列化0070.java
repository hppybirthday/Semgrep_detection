import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import org.springframework.web.bind.annotation.*;
import java.util.List;

@RestController
@RequestMapping("/device")
public class IoTDeviceController {
    
    @Autowired
    private DeviceConfigService deviceConfigService;

    @PostMapping("/config")
    public String updateDeviceConfig(@RequestParam String deviceId, 
                                   @RequestParam String columnComment) {
        // 存储恶意JSON数据到Redis缓存
        deviceConfigService.cacheColumnComment(deviceId, columnComment);
        return "Config updated";
    }
}

@Service
class DeviceConfigService {
    
    @Autowired
    private RedisTemplate<String, String> redisTemplate;

    // 将用户输入直接存储到Redis
    public void cacheColumnComment(String deviceId, String columnComment) {
        redisTemplate.opsForValue().set("device:config:" + deviceId, columnComment);
    }

    // 从Redis反序列化缓存数据（存在漏洞）
    public List<String> getCacheDynamicDataSourceModel(String deviceId) {
        String json = redisTemplate.opsForValue().get("device:config:" + deviceId);
        if (json != null) {
            // 使用存在漏洞的JSON反序列化
            return JsonUtils.deserialize(json);
        }
        return null;
    }
}

// 模拟JsonUtils工具类（内部使用FastJSON实现）
class JsonUtils {
    // 存在漏洞的反序列化实现
    public static List<String> deserialize(String json) {
        // 实际可能使用了FastJSON的parseObject方法：
        // return JSON.parseObject(json, List.class);
        // 未指定类型安全参数，允许任意类型转换
        return (List<String>) java.util.Arrays.asList(json.split(",")); // 简化模拟
    }
}

// Spring Boot启动类
@SpringBootApplication
public class Application {
    public static void main(String[] args) {
        SpringApplication.run(Application.class, args);
    }
}