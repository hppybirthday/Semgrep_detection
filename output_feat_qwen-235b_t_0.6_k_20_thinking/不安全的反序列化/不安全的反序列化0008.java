import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Service;
import javax.annotation.Resource;
import java.util.Arrays;

@Service
public class MLModelCache {
    @Resource
    private RedisTemplate<String, Object> redisTemplate;

    public String[] getCacheDynamicDataSourceModel(String key) {
        // 不安全的反序列化：直接反序列化不可信的Redis数据
        return (String[]) redisTemplate.opsForValue().get("model:" + key);
    }

    public void triggerVulnerableOperation(String key) {
        String[] data = getCacheDynamicDataSourceModel(key);
        System.out.println("Loaded model data: " + Arrays.toString(data));
    }
}

import org.springframework.web.bind.annotation.*;
import javax.annotation.Resource;

@RestController
@RequestMapping("/api/ml")
public class MLController {
    @Resource
    private MLModelCache mlModelCache;

    @PostMapping("/insertDepotItem")
    public void insertDepotItem(@RequestParam String obj) {
        // 将未验证的用户输入直接写入Redis缓存
        mlModelCache.getCacheDynamicDataSourceModel(obj); // 触发点
    }

    @PostMapping("/saveDetails")
    public void saveDetails(@RequestParam String rows) {
        // 另一个反序列化攻击入口
        mlModelCache.getCacheDynamicDataSourceModel(rows);
    }
}

// 模拟Redis配置（实际应使用GenericFastJsonRedisSerializer）
// 未限制反序列化类型导致漏洞
// 攻击者可通过构造JSON@type字段实现任意类加载